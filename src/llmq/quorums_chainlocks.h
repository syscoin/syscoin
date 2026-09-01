// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H
#define SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H

#include <evo/auxiliary_history_gc.h>
#include <evo/pq_payment_probation.h>
#include <util/ranges.h>
#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_chainlock_persistence.h>
#include <llmq/pq_chainlock_signer.h>
#include <llmq/pq_chainlock_store.h>
#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_signer.h>
#include <llmq/pq_payment_audit_staging_store.h>
#include <llmq/pq_payment_audit_store.h>
#include <llmq/pq_payment_audit_verify.h>
#include <llmq/pq_quorum_builder.h>
#include <protocol.h>
#include <saltedhasher.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CChain;
class CConnman;
class CDataStream;
class CNode;
class CScheduler;
class ChainstateManager;
class PeerManager;
typedef int64_t NodeId;

namespace Consensus {
struct Params;
}

namespace llmq {

namespace test {
class CChainLocksHandlerTestAccess;
}

namespace pq {
class PQPaymentProbationTransitionView;
}

/**
 * Linearizable admission fence for work that completes outside handler locks.
 * The complete open state is the token, so no reader can observe a partially
 * published lifecycle, health, or failure transition.
 */
class ShareAdmissionGate {
public:
    struct Observation {
        uint64_t state;

        [[nodiscard]] bool operator==(const Observation& other) const noexcept
        {
            return state == other.state;
        }
    };

    [[nodiscard]] Observation Observe() const noexcept
    {
        return Observation{m_state.load()};
    }

    /** Publish one state evaluation only if nothing changed while it ran. */
    [[nodiscard]] bool TryPublishEnabled(
        Observation observation, bool enabled) noexcept
    {
        uint64_t expected{observation.state};
        uint64_t flags{expected & FLAGS_MASK};
        flags = enabled ? flags | ENABLED : flags & ~ENABLED;
        flags = Normalize(flags);
        if (flags == (expected & FLAGS_MASK) &&
            ((flags & OPEN) != 0 || (flags & TERMINAL) != 0)) {
            return m_state.load() == expected;
        }
        return m_state.compare_exchange_strong(
            expected, Advance(expected, flags));
    }

    /** Lifecycle transitions invalidate every observation and work token. */
    void SetReady(bool ready) noexcept
    {
        uint64_t state{m_state.load()};
        while (true) {
            uint64_t flags{state & FLAGS_MASK};
            flags = ready ? flags | READY : flags & ~READY;
            if (m_state.compare_exchange_weak(
                    state, Advance(state, flags))) {
                return;
            }
        }
    }

    /** Terminal failures are sticky and invalidate work even when closed. */
    void Fail() noexcept
    {
        uint64_t state{m_state.load()};
        while (true) {
            uint64_t flags{state & FLAGS_MASK};
            flags = (flags | TERMINAL) & ~ENABLED;
            if (m_state.compare_exchange_weak(
                    state, Advance(state, flags))) {
                return;
            }
        }
    }

    [[nodiscard]] uint64_t Acquire() const noexcept
    {
        const uint64_t state{m_state.load()};
        return (state & OPEN) != 0 ? state : 0;
    }

    [[nodiscard]] bool IsCurrent(uint64_t token) const noexcept
    {
        return token != 0 && (token & OPEN) != 0 &&
               m_state.load() == token;
    }

    [[nodiscard]] bool IsOpen() const noexcept
    {
        return (m_state.load() & OPEN) != 0;
    }

    [[nodiscard]] bool IsTerminal() const noexcept
    {
        return (m_state.load() & TERMINAL) != 0;
    }

private:
    static constexpr uint64_t OPEN{uint64_t{1} << 0};
    static constexpr uint64_t READY{uint64_t{1} << 1};
    static constexpr uint64_t ENABLED{uint64_t{1} << 2};
    static constexpr uint64_t TERMINAL{uint64_t{1} << 3};
    static constexpr uint64_t REVISION_STEP{uint64_t{1} << 4};
    static constexpr uint64_t FLAGS_MASK{REVISION_STEP - 1};
    static constexpr uint64_t REVISION_MASK{~FLAGS_MASK};

    [[nodiscard]] static uint64_t Normalize(uint64_t flags) noexcept
    {
        flags &= FLAGS_MASK;
        if ((flags & TERMINAL) != 0) flags &= ~ENABLED;
        if ((flags & READY) != 0 && (flags & ENABLED) != 0 &&
            (flags & TERMINAL) == 0) {
            return flags | OPEN;
        }
        return flags & ~OPEN;
    }

    [[nodiscard]] static uint64_t Advance(
        uint64_t state, uint64_t flags) noexcept
    {
        flags = Normalize(flags);
        const uint64_t revision{state & REVISION_MASK};
        // Saturation is unreachable in practice, but wrapping could revive an
        // ancient token, so exhaustion permanently fails closed.
        if (revision == REVISION_MASK) return TERMINAL;
        return revision + REVISION_STEP + flags;
    }

    std::atomic<uint64_t> m_state{0};
};

/**
 * Serialize destructive-history authority with lifecycle, health, and newer
 * durability barriers. Expensive proof construction happens outside this
 * gate; its generation prevents that work from publishing stale authority.
 */
class AuxiliaryHistoryGCAuthorizationGate {
public:
    using Token = uint64_t;

    enum class MutationResult : uint8_t {
        STALE = 0,
        APPLIED,
        FAILED,
    };

    template <typename Revoke>
    [[nodiscard]] bool Start(Revoke&& revoke)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (m_state == State::FAILED || !AdvanceLocked()) {
            m_state = State::FAILED;
            (void)revoke();
            return false;
        }
        m_state = State::STARTING;
        if (!revoke()) {
            m_state = State::FAILED;
            return false;
        }
        return true;
    }

    template <typename Revoke>
    void Stop(Revoke&& revoke)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (m_state != State::FAILED) {
            if (AdvanceLocked()) {
                m_state = State::STOPPED;
            } else {
                m_state = State::FAILED;
            }
        }
        if (!revoke()) m_state = State::FAILED;
    }

    template <typename Revoke>
    void Fail(Revoke&& revoke)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (m_state != State::FAILED) {
            (void)AdvanceLocked();
            m_state = State::FAILED;
        }
        (void)revoke();
    }

    template <typename Revoke>
    [[nodiscard]] bool SetHealthy(bool healthy, Revoke&& revoke)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (m_state == State::STOPPED || m_state == State::FAILED) {
            return false;
        }
        if (healthy) {
            if (m_state == State::READY) return true;
            if (!AdvanceLocked()) {
                m_state = State::FAILED;
                (void)revoke();
                return false;
            }
            m_state = State::READY;
            return true;
        }
        if (m_state == State::STARTING) return false;
        if (!AdvanceLocked()) {
            m_state = State::FAILED;
        } else {
            m_state = State::STARTING;
        }
        if (!revoke()) m_state = State::FAILED;
        return false;
    }

    template <typename Arm>
    [[nodiscard]] bool ArmPublication(Arm&& arm)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (!AdvanceLocked()) m_state = State::FAILED;
        if (!arm()) {
            m_state = State::FAILED;
            return false;
        }
        return m_state != State::FAILED;
    }

    [[nodiscard]] std::optional<Token> ObserveReady() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        return m_state == State::READY
            ? std::optional<Token>{m_generation}
            : std::nullopt;
    }

    template <typename RevokeFn>
    [[nodiscard]] MutationResult Revoke(RevokeFn&& revoke)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (!AdvanceLocked()) m_state = State::FAILED;
        if (!revoke()) m_state = State::FAILED;
        return m_state == State::FAILED ? MutationResult::FAILED
                                        : MutationResult::APPLIED;
    }

    template <typename Publish>
    [[nodiscard]] MutationResult TryPublish(Token token, Publish&& publish)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        LOCK(m_mutex);
        if (m_state != State::READY || token != m_generation) {
            return MutationResult::STALE;
        }
        // Consume the observation before exposing authority so another
        // positive proof built from the same generation cannot republish it.
        if (!AdvanceLocked()) {
            m_state = State::FAILED;
            return MutationResult::FAILED;
        }
        if (publish()) return MutationResult::APPLIED;
        m_state = State::FAILED;
        return MutationResult::FAILED;
    }

private:
    enum class State : uint8_t {
        STOPPED = 0,
        STARTING,
        READY,
        FAILED,
    };

    [[nodiscard]] bool AdvanceLocked() EXCLUSIVE_LOCKS_REQUIRED(m_mutex)
    {
        if (m_generation == std::numeric_limits<uint64_t>::max()) {
            return false;
        }
        ++m_generation;
        return true;
    }

    mutable Mutex m_mutex;
    State m_state GUARDED_BY(m_mutex){State::STOPPED};
    uint64_t m_generation GUARDED_BY(m_mutex){0};
};

/** Compact immutable facts derived from one fully validated archive witness. */
struct PaymentAuditCandidateMetadata {
    pq::PaymentAuditStatement statement;
    uint256 logical_id;
    uint256 witness_id;
    uint256 commitment_hash;
    uint256 result_hash;
    pq::QuorumBitmap online_members{};

    friend bool operator==(const PaymentAuditCandidateMetadata&,
                           const PaymentAuditCandidateMetadata&) = default;
};

/** One coherent ordered archive view without retaining certificate payloads. */
struct PaymentAuditCandidateMetadataSnapshot {
    uint64_t candidate_revision{0};
    uint32_t epoch{0};
    std::vector<PaymentAuditCandidateMetadata> ordered_candidates;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool ContainsExactStatement(
        const pq::PaymentAuditStatement& statement) const noexcept;
    friend bool operator==(const PaymentAuditCandidateMetadataSnapshot&,
                           const PaymentAuditCandidateMetadataSnapshot&) =
        default;
};

using PaymentAuditCandidateMetadataSnapshotPtr =
    std::shared_ptr<const PaymentAuditCandidateMetadataSnapshot>;

/**
 * Handler-owned memoization of the immutable candidate facts at one exact
 * process-local archive revision. A cache instance must never outlive or be
 * shared across its owning PaymentAuditStore instance.
 */
class PaymentAuditCandidateMetadataCache final {
public:
    static constexpr std::size_t CAPACITY{16};

    struct Key {
        uint32_t epoch{0};
        uint64_t candidate_revision{0};

        friend bool operator==(const Key&, const Key&) = default;
    };

    struct Stats {
        std::size_t entries{0};
        uint64_t hits{0};
        uint64_t builds{0};
        uint64_t conflicts{0};
    };

    [[nodiscard]] PaymentAuditCandidateMetadataSnapshotPtr Get(
        const Key& key) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Reject a conflicting publication while retaining the first value. */
    [[nodiscard]] PaymentAuditCandidateMetadataSnapshotPtr Publish(
        const Key& key, PaymentAuditCandidateMetadataSnapshot snapshot)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Load and derive at most once for the observed healthy store revision.
     * Stale revisions and every load/derivation failure return no value.
     */
    [[nodiscard]] PaymentAuditCandidateMetadataSnapshotPtr GetOrBuild(
        const pq::PaymentAuditStore& store,
        const uint256& genesis_hash,
        uint32_t epoch)
        EXCLUSIVE_LOCKS_REQUIRED(!m_build_mutex, !m_mutex);
    void Clear()
        EXCLUSIVE_LOCKS_REQUIRED(!m_build_mutex, !m_mutex);
    [[nodiscard]] Stats StatsForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Entry {
        Key key;
        PaymentAuditCandidateMetadataSnapshotPtr snapshot;
        bool occupied{false};
        bool recently_used{false};
    };

    mutable Mutex m_build_mutex;
    mutable Mutex m_mutex;
    mutable std::array<Entry, CAPACITY> m_entries GUARDED_BY(m_mutex);
    mutable std::size_t m_clock GUARDED_BY(m_mutex){0};
    mutable uint64_t m_hits GUARDED_BY(m_mutex){0};
    mutable uint64_t m_builds GUARDED_BY(m_mutex){0};
    mutable uint64_t m_conflicts GUARDED_BY(m_mutex){0};
};

/**
 * Bounded memoization for miner-only payment-audit receipt construction.
 * Null results are deliberately excluded because missing local context can
 * become available without changing the archive candidate revision.
 */
class PaymentAuditReceiptCache final {
public:
    static constexpr std::size_t CAPACITY{64};

    struct Key {
        uint256 carrier_parent_hash;
        int32_t carrier_parent_height{-1};
        uint256 parent_probation_state_hash;
        int32_t carrier_height{-1};
        uint32_t epoch{0};
        uint64_t archive_revision{0};

        friend bool operator==(const Key&, const Key&) = default;
    };

    struct Stats {
        std::size_t entries{0};
        uint64_t hits{0};
        uint64_t builds{0};
        uint64_t conflicts{0};
    };

    [[nodiscard]] std::optional<pq::PaymentAuditReceipt> Get(
        const Key& key) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Reject a conflicting publication while retaining the established value.
     */
    [[nodiscard]] std::optional<pq::PaymentAuditReceipt> Publish(
        const Key& key, const pq::PaymentAuditReceipt& receipt)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void Clear() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] Stats StatsForTesting() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Entry {
        Key key;
        pq::PaymentAuditReceipt receipt;
        bool occupied{false};
        bool recently_used{false};
    };

    mutable Mutex m_mutex;
    mutable std::array<Entry, CAPACITY> m_entries GUARDED_BY(m_mutex);
    mutable std::size_t m_clock GUARDED_BY(m_mutex){0};
    mutable uint64_t m_hits GUARDED_BY(m_mutex){0};
    mutable uint64_t m_builds GUARDED_BY(m_mutex){0};
    mutable uint64_t m_conflicts GUARDED_BY(m_mutex){0};
};

/** Live production may stop while an exact requested historical witness heals. */
[[nodiscard]] bool IsPaymentAuditCertificateIngressAllowed(
    bool operational, bool local_certificate,
    bool required_remote_response) noexcept;

/** A required exact response must never fall through to live verification. */
[[nodiscard]] bool MustRetryPaymentAuditCertificateContext(
    bool historical_required, bool historical_resolved) noexcept;

/** Retry only a deterministic local journal replay that we already collected. */
[[nodiscard]] bool ShouldRetryLocalChainLockShareRelay(
    bool journal_replayed, pq::ShareCollectionResult result) noexcept;

enum class FinalChainLockVerificationPath : uint8_t {
    FULL = 0,
    COLLECTED,
};

/**
 * Reuse share-level verification only for the exact process-local certificate
 * and immutable live context that produced it. Every mismatch must take the
 * ordinary full-certificate verification path.
 */
[[nodiscard]] FinalChainLockVerificationPath
SelectFinalChainLockVerificationPath(
    const pq::CollectedChainLockFinalization* collected,
    const pq::FinalChainLock* certificate,
    const uint256& genesis_hash,
    const pq::ChainLockScheduleConfig& schedule,
    const pq::VerifiedRosterSetPtr& roster_set,
    uint8_t authorization_mask,
    bool local_live_admission,
    bool admission_generation_current,
    bool collector_generation_current) noexcept;

enum class FinalPaymentAuditVerificationPath : uint8_t {
    FULL = 0,
    COLLECTED,
};

/** Local aggregate authority never survives replacement of its live runtime. */
[[nodiscard]] bool IsPaymentAuditVerificationPathAuthorized(
    bool local_certificate,
    FinalPaymentAuditVerificationPath path) noexcept;

/** Only an exact live collector proof may bypass final audit WOTS checks. */
[[nodiscard]] FinalPaymentAuditVerificationPath
SelectFinalPaymentAuditVerificationPath(
    const pq::CollectedPaymentAuditFinalization* collected,
    const pq::FinalPaymentAudit* certificate,
    const uint256& genesis_hash,
    const pq::PaymentAuditScheduleConfig& schedule,
    const pq::VerifiedRosterSetPtr& roster_set,
    uint8_t authorization_mask,
    bool local_live_admission,
    bool admission_generation_current,
    bool runtime_generation_current,
    bool roster_source_generation_current) noexcept;

/** Retry one immutable local aggregate without repeating scheduled-WOTS work. */
[[nodiscard]] bool IsPaymentAuditFinalizationRetryDue(
    std::chrono::microseconds now,
    std::optional<std::chrono::microseconds> last_attempt) noexcept;

/** Retire work whose roster source changed or whose final proof was revoked. */
[[nodiscard]] bool ShouldResetPaymentAuditRuntime(
    bool finalized,
    uint64_t finalization_admission_generation,
    uint64_t current_admission_generation,
    uint64_t runtime_roster_source_generation,
    uint64_t current_roster_source_generation) noexcept;

/** Every post-verification side effect belongs to one immutable runtime. */
[[nodiscard]] bool IsExactPaymentAuditRuntimeBinding(
    bool runtime_present,
    bool collector_present,
    bool generation_matches,
    bool statement_matches,
    bool prepared_context_matches,
    bool relay_recipients_match) noexcept;

/** Preserve only a collector for the exact successor view opened by a winner. */
[[nodiscard]] bool IsChainLockCollectorOnAcceptedSuccessorView(
    const pq::ChainLockScheduleConfig& schedule,
    const pq::ChainLockStatement& collector,
    const pq::ChainLockStatement& winner) noexcept;

/** A prior process could only have consumed targets signable at this tip. */
[[nodiscard]] bool ShouldConsumeChainLockStartupSlot(
    const pq::ChainLockScheduleConfig& schedule,
    int32_t startup_tip_height,
    int32_t target_height) noexcept;

/** A durable precommit keeps its target until a disjoint attempt is signable. */
[[nodiscard]] std::optional<pq::ChainLockSigningWindow>
StagedRecoverySigningWindow(
    const pq::ChainLockScheduleConfig& chainlock,
    const pq::BTCCScheduleConfig& btcc,
    const pq::RosterRecoveryPrecommit& precommit,
    int32_t durable_predecessor_height,
    int32_t tip_height) noexcept;

struct StagedRecoverySigningWindowSelection {
    pq::ChainLockSigningWindow window;
    bool rolls_pending_epoch{false};
};

/** Move only an unsigned, stably inactive attempt to a signable disjoint epoch. */
[[nodiscard]] std::optional<StagedRecoverySigningWindowSelection>
SelectStagedRecoverySigningWindow(
    const pq::ChainLockScheduleConfig& chainlock,
    const pq::BTCCScheduleConfig& btcc,
    const pq::RosterRecoveryPrecommit& precommit,
    int32_t durable_predecessor_height,
    int32_t tip_height,
    bool anchor_stably_inactive) noexcept;

/** The live audit-signing interval starts after the seal and ends exclusively. */
[[nodiscard]] bool IsPaymentAuditSigningHeightLive(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t tip_height) noexcept;

/** A prior process could have signed once the audit window opened. */
[[nodiscard]] bool ShouldConsumePaymentAuditStartupSlot(
    const pq::PaymentAuditScheduleConfig& schedule,
    uint32_t subject_epoch,
    int32_t startup_tip_height) noexcept;

/** Prevent delayed partition signatures from finalizing a stale or deep fork. */
[[nodiscard]] bool IsLiveChainLockCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept;

/** Recovery has the same current-round fork bound as ordinary live finality. */
[[nodiscard]] bool IsCurrentChainLockCatchupCandidateAdmissible(
    const pq::ChainLockScheduleConfig& schedule,
    const CBlockIndex& active_tip,
    const CBlockIndex& candidate) noexcept;

/** A durable receipt-replay obligation cannot be orphaned by current finality. */
[[nodiscard]] bool IsCurrentChainLockCandidateBlockedByPreseal(
    bool candidate_is_active,
    bool current_round_candidate,
    bool has_btcc_preseal,
    bool has_payment_audit_preseal) noexcept;

/** Only current branch-derived recovery may revise an exact local cursor view. */
[[nodiscard]] bool IsHistoricalLocalPredecessorCursorCompatible(
    bool current_round_candidate,
    bool declared_predecessor_is_local,
    const pq::BTCCursor& declared_cursor,
    const pq::BTCCursor& local_cursor) noexcept;

struct CurrentChainLockBTCCSelection {
    pq::BTCCursor previous_cursor;
    pq::BTCCSelection selected;
    std::optional<pq::BTCCCursorReconciliationProof> cursor_reconciliation;
};

/** Select one branch-derived BTCC view without making a missed receipt permanent. */
[[nodiscard]] std::optional<CurrentChainLockBTCCSelection>
SelectCurrentChainLockBTCC(
    const uint256& genesis_hash,
    const pq::ChainLockFinalityStoreConfig& config,
    const CBlockIndex& target,
    const pq::FinalChainLockRecordMetadata* durable_best)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

// Compatibility names retain the narrow integration surface while the wire
// object and every signature are post-quantum.
class CChainLockSig : public pq::FinalChainLock {
public:
    CChainLockSig() = default;
    CChainLockSig(const pq::FinalChainLock& other) : pq::FinalChainLock{other} {}
    CChainLockSig(pq::FinalChainLock&& other)
        : pq::FinalChainLock{std::move(other)} {}

    CChainLockSig& operator=(pq::FinalChainLock other)
    {
        static_cast<pq::FinalChainLock&>(*this) = std::move(other);
        return *this;
    }

    [[nodiscard]] bool IsNull() const noexcept
    {
        return statement.height == -1 && statement.block_hash.IsNull();
    }
    [[nodiscard]] std::string ToString() const;
};
// The store owns the immutable wire object as its base type; callers do not
// need the compatibility wrapper used at deserialization boundaries.
using CChainLockSigCPtr = std::shared_ptr<const pq::FinalChainLock>;

/** Return null until every fork-pinned deployment parameter is usable. */
[[nodiscard]] std::optional<pq::ChainLockFinalityStoreConfig>
MakePQChainLockFinalityStoreConfig(const Consensus::Params& consensus);

/** Return null unless roster and registry cutoffs form one safe profile. */
[[nodiscard]] std::optional<pq::QuorumBuildConfig>
MakePQQuorumBuildConfig(const Consensus::Params& consensus);

/** Bounded worker policy used by the live fixed-profile signature verifier. */
[[nodiscard]] std::size_t GetPQChainLockVerifierThreads(
    unsigned int hardware_threads) noexcept;

/** Checkpoint GC must not strand background AssumeUTXO validation. */
[[nodiscard]] std::optional<std::vector<uint256>>
CollectChainstatePaymentProbationRoots(ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

enum class PaymentAuditContextStatus : uint8_t {
    READY = 0,
    INVALID,
    LOCAL_ERROR,
};

enum class HistoricalIndexValidationMode : uint8_t {
    BTCC_COMPAT = 0,
    FULL_RECEIPT,
    FULL_FINALITY,
};

enum class BTCCCatchupRangeStatus : uint8_t;

/**
 * Bounded progress over one of a small number of immutable branch ranges.
 * A transient result retains the exact next block, so finality recovery can
 * resume without monopolizing cs_main after an arbitrarily long outage.
 */
class HistoricalIndexValidationCache final {
public:
    static constexpr std::size_t CAPACITY{16};
    static constexpr std::size_t BLOCK_BUDGET{4096};

    [[nodiscard]] PaymentAuditContextStatus Validate(
        const CBlockIndex& last,
        int32_t first_height,
        HistoricalIndexValidationMode mode,
        uint64_t provenance_revocation_revision,
        std::size_t block_budget = BLOCK_BUDGET,
        std::size_t* examined_blocks = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    struct Entry {
        bool occupied{false};
        bool recently_used{false};
        HistoricalIndexValidationMode mode{
            HistoricalIndexValidationMode::BTCC_COMPAT};
        uint64_t provenance_revocation_revision{0};
        int32_t last_height{-1};
        uint256 last_hash;
        int32_t first_height{-1};
        int32_t next_height{-1};
    };

    std::array<Entry, CAPACITY> m_entries{};
    std::size_t m_clock{0};
};

enum class BoundedActiveRangeStatus : uint8_t {
    INVALID = 0,
    COMPLETE,
    WORK,
};

struct BoundedActiveRangePlan {
    BoundedActiveRangeStatus status{BoundedActiveRangeStatus::INVALID};
    int32_t first_height{-1};
    int32_t last_height{-1};
    bool reset{false};
};

/** Process-local progress over one exact active-chain source and floor. */
class BoundedActiveRangeFrontier final {
public:
    [[nodiscard]] BoundedActiveRangePlan Plan(
        const CChain& active_chain,
        const CBlockIndex& active_tip,
        int32_t floor_height,
        const uint256& floor_hash,
        const uint256& source_token,
        std::size_t block_budget)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    [[nodiscard]] bool CommitThrough(
        const CChain& active_chain,
        int32_t through_height)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    [[nodiscard]] bool IsComplete(
        const CBlockIndex& active_tip) const noexcept
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    [[nodiscard]] int32_t ValidatedThroughHeight() const noexcept
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return m_validated_through_height;
    }

private:
    bool m_initialized{false};
    uint256 m_source_token;
    int32_t m_floor_height{-1};
    uint256 m_floor_hash;
    int32_t m_validated_through_height{-1};
    uint256 m_validated_through_hash;
    bool m_plan_pending{false};
    int32_t m_planned_first{-1};
    int32_t m_planned_last{-1};
};

enum class PaymentAuditSealValidation : uint8_t {
    LIVE_EXACT = 0,
    THRESHOLD_ATTESTED_HISTORY,
};

/** Distinguish peer-invalid audit context from incomplete local indexing. */
[[nodiscard]] PaymentAuditContextStatus ClassifyPaymentAuditSealContext(
    const CBlockIndex* seal, int32_t expected_height,
    int32_t predecessor_height, const uint256& predecessor_hash,
    PaymentAuditSealValidation validation)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Distinguish a failed response block from one not locally ready yet. */
[[nodiscard]] PaymentAuditContextStatus ClassifyPaymentAuditResponseContext(
    const CBlockIndex* response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/**
 * Historical audit certificates authenticate the selected response context,
 * so a fully validated pruned index remains usable without its block body.
 * Live signing additionally requires the body used to build local staging.
 */
[[nodiscard]] bool IsPaymentAuditResponseBlockUsable(
    const CBlockIndex& response, bool require_block_data) noexcept
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Reject a malformed carrier before an unavailable witness can defer it. */
[[nodiscard]] PaymentAuditContextStatus
ClassifyPaymentAuditReceiptCarrierContext(
    const pq::PaymentAuditReceipt& receipt,
    const CBlockIndex& carrier,
    const pq::PaymentAuditScheduleConfig& schedule)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Recover only the exact receipt committed by a deferred carrier block. */
[[nodiscard]] std::optional<pq::PaymentAuditReceipt>
ExtractDeferredPaymentAuditReceipt(
    const CBlock& carrier_block,
    const uint256& required_witness_id,
    const CBlockIndex& carrier,
    const CBlockIndex& best_candidate)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

using ChainLockRelayRecipients =
    std::unordered_set<uint256, StaticSaltedHasher>;

[[nodiscard]] ChainLockRelayRecipients BuildChainLockRelayRecipients(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters);

/**
 * Authenticate the transport relay independently from the share's original
 * signer. Both must be in the frozen context, but multi-hop gossip means they
 * are not required to be the same operator.
 */
[[nodiscard]] bool IsAuthorizedChainLockShareRelay(
    const std::array<pq::FrozenQuorumRoster, pq::ACTIVE_QUORUMS>& rosters,
    const ChainLockRelayRecipients& relay_recipients,
    const uint256& relay_pro_tx_hash,
    const pq::ChainLockShareTranscript& transcript) noexcept;

class CChainLocksHandler;
class VerifiedPaymentAuditReceiptTransition;
class VerifiedPaymentAuditReceiptTransitionCache;

/**
 * Process-local proof that one exact receipt certificate and its derived
 * probation transition were fully verified. Its definition and construction
 * stay private to the handler implementation.
 */
using VerifiedPaymentAuditReceiptTransitionPtr =
    std::shared_ptr<const VerifiedPaymentAuditReceiptTransition>;
[[nodiscard]] const pq::PQPaymentProbationTransitionView*
GetVerifiedPaymentAuditReceiptTransition(
    const VerifiedPaymentAuditReceiptTransitionPtr& verified) noexcept;

/**
 * Live certificate and authenticated scheduled-WOTS-share handler. There is no DKG,
 * threshold-key ceremony, recovered-signature layer, or BLS state.
 */
class CChainLocksHandler final : private pq::ChainLockFinalityContext {
    struct LocalChainLockFinalization;

public:
    CChainLocksHandler(CConnman& connman,
                       PeerManager& peerman,
                       ChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    ~CChainLocksHandler();

    CChainLocksHandler(const CChainLocksHandler&) = delete;
    CChainLocksHandler& operator=(const CChainLocksHandler&) = delete;

    void Start()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lifecycle_mutex,
                                 !m_share_lifecycle_mutex,
                                 !m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_share_signing_mutex,
                                 !m_btcc_preseal_mutex);
    void Stop()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lifecycle_mutex,
                                 !m_share_lifecycle_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex);

    /**
     * Install the immutable branch-bound roster service. An absent service
     * makes incoming certificates transiently unverifiable rather than
     * trusted.
     */
    void SetQuorumRosterCache(pq::FrozenQuorumRosterCachePtr cache)
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);

    [[nodiscard]] bool AlreadyHave(const uint256& logical_id) const;
    [[nodiscard]] bool GetChainLockByHash(const uint256& logical_id,
                                          CChainLockSig& result) const;
    [[nodiscard]] CChainLockSigCPtr GetMostRecentChainLock() const;
    [[nodiscard]] CChainLockSigCPtr GetBestChainLock() const;
    /** Build one target from the exact currently accepted roster authority. */
    [[nodiscard]] pq::VerifiedRosterSetPtr GetVerifiedRosterSetForAccepted(
        const pq::FinalChainLock& accepted,
        int32_t target_height,
        const CBlockIndex& target,
        pq::QuorumBuildError* error = nullptr) const;
    /** Immutable/dynamic payload retained by live payment-audit machinery. */
    [[nodiscard]] std::size_t GetPaymentAuditRuntimePinnedBytes() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_payment_audit_mutex);
    [[nodiscard]] const CBlockIndex* GetBestChainLockIndex() const;
    /** Read the healthy fsynced winner before live-store import. */
    [[nodiscard]] std::optional<evo::AuxiliaryHistoryGCBlockIdentity>
    GetDurableFinalityTargetForStartup() const;
    enum class DurableFinalityRecoveryMode : uint8_t {
        REQUIRE_VALIDATED,
        BLOCK_INDEX_REPLAY,
    };
    /**
     * Resolve the active-chain floor protected by the fsynced winner before
     * Start() imports it into the live store. If the winner is on a validated
     * side branch, its active-chain fork is protected until normal finality
     * enforcement can activate it. Block-index replay may use the exact
     * transaction-valid target as a provisional ancestry constraint while
     * ConnectBlock performs the remaining script validation.
    */
    [[nodiscard]] bool GetDurableFinalityRecoveryFloor(
        const CBlockIndex*& active_floor,
        const CBlockIndex*& durable_target,
        std::string& error,
        DurableFinalityRecoveryMode mode =
            DurableFinalityRecoveryMode::REQUIRE_VALIDATED,
        bool* replay_target_pending = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool GetRecentChainLockByHeight(
        int32_t height, CChainLockSig& result) const;

    /** Exact payment-audit certificates remain independently retrievable. */
    [[nodiscard]] bool AlreadyHavePaymentAudit(
        const uint256& witness_id) const;
    [[nodiscard]] bool GetPaymentAuditByHash(
        const uint256& witness_id,
        pq::FinalPaymentAudit& result) const;

    enum class PaymentAuditReceiptCertificateStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
        UNAVAILABLE,
        LOCAL_ERROR,
    };

    /** Keep local archive failures out of peer-controlled consensus verdicts. */
    [[nodiscard]] static PaymentAuditReceiptCertificateStatus
    ClassifyPaymentAuditArchiveRead(bool store_available,
                                    bool healthy_before_read,
                                    bool witness_found,
                                    bool healthy_after_read) noexcept;
    [[nodiscard]] static PaymentAuditReceiptCertificateStatus
    ClassifyPaymentAuditArchiveMutation(
        pq::PaymentAuditStoreResult result) noexcept;
    [[nodiscard]] static bool IsPaymentAuditLocalRosterBuildError(
        pq::QuorumBuildError error) noexcept;

    /** Called only after the exact receipt transition is applied. */
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    PinPaymentAuditReceiptCertificate(
        uint32_t epoch, const uint256& witness_id);

    /** Build the canonical null-or-audit receipt for one scheduled slot. */
    [[nodiscard]] pq::PaymentAuditReceipt
    GetPaymentAuditReceiptForCarrier(
        int32_t carrier_height,
        const CBlockIndex& carrier_parent) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex);

    /**
     * Bind a receipt to its certificate and exact probation transition.
     * The owning result is reset on entry and must be consumed synchronously
     * under the caller's continuously held cs_main branch snapshot.
     */
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    CheckPaymentAuditReceiptCertificate(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier,
        VerifiedPaymentAuditReceiptTransitionPtr& transition) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_lookup_mutex,
                                 !m_verification_mutex);

    /** Build the fixed-cadence carrier from a fully verified recent ADVANCE. */
    [[nodiscard]] pq::BTCCReceipt GetBTCCReceiptForCarrier(
        int32_t carrier_height,
        const CBlockIndex& carrier_parent) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    enum class BTCCReceiptCertificateStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
    };

    /** Bind a non-null receipt to the exact locally verified ADVANCE winner. */
    [[nodiscard]] BTCCReceiptCertificateStatus CheckBTCCReceiptCertificate(
        const pq::BTCCReceipt& receipt,
        const CBlockIndex& carrier) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /** Queue the single exact certificate blocking live carrier activation. */
    void NotePendingBTCCReceiptCertificate(
        const uint256& logical_id,
        const CBlockIndex& carrier)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_pending_btcc_receipt_mutex);
    [[nodiscard]] bool IsPendingBTCCReceiptCertificate(
        const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex);
    [[nodiscard]] bool IsRequiredBTCCReceiptCertificate(
        const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    void NotePendingPaymentAuditReceiptCertificate(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier)
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool IsPendingPaymentAuditReceiptCertificate(
        const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex);

    /**
     * Persist the first historical non-null receipt whose certificate is not
     * locally available. Base-chain validation may continue, but NEVM delivery
     * and new signing stay deferred until catch-up authenticates the prefix.
     * The durable marker remains afterward as a separate Geth replay
     * obligation until the authenticated blocks have actually been delivered.
     */
    [[nodiscard]] bool BeginBTCCPreseal(
        const CBlockIndex& carrier,
        const pq::BTCCReceipt& missing_receipt)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsBTCCPresealActive() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool HasNEVMReplayObligation() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool ShouldDeferBTCCNEVM(
        const CBlockIndex& index) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsBTCCPrefixAuthenticated(
        const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * Rebuild the payment-only transition context carried compactly by a
     * receipt. The receipt remains provisional until a descendant ChainLock
     * authenticates the resulting cumulative receipt and probation roots.
     */
    [[nodiscard]] PaymentAuditContextStatus
    BuildCompactPaymentAuditTransitionContext(
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier,
        pq::PQPaymentProbationTransitionContext& context) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_lookup_mutex);
    [[nodiscard]] bool BeginPaymentAuditPreseal(
        const CBlockIndex& carrier,
        const pq::PaymentAuditReceipt& missing_receipt,
        const pq::PaymentAuditReceiptState& predecessor_receipt_state,
        const uint256& predecessor_probation_state_hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPaymentAuditPresealActive() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPaymentAuditPrefixAuthenticated(
        const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool IsPaymentAuditCheckpointAuthenticated(
        const pq::PaymentAuditStoreCheckpoint& checkpoint,
        const CBlockIndex& index) const EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    void ProcessMessage(CNode* from,
                        const std::string& command,
                        CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_signer_reconcile_mutex);

    [[nodiscard]] bool ProcessNewChainLock(
        NodeId from,
        const CChainLockSig& chainlock,
        BlockValidationState& state,
        bool* peer_fault = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);

    void NotifyHeaderTip(const CBlockIndex* new_tip)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void UpdatedBlockTip(const CBlockIndex* new_tip, bool initial_download)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void CheckActiveState()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool GetCLSIGFromPeers()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex);

    [[nodiscard]] bool HasChainLock(int32_t height,
                                    const uint256& block_hash) const;
    [[nodiscard]] bool HasConflictingChainLock(
        int32_t height, const uint256& block_hash) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    friend class test::CChainLocksHandlerTestAccess;

    enum class HistoricalAdmission : uint8_t {
        NONE = 0,
        CURRENT_CATCHUP,
        RECOVERY,
        PRESEAL_CATCHUP,
        PRESEAL_RECEIPT,
    };

    struct HistoricalAdmissionContext {
        HistoricalAdmission admission{HistoricalAdmission::NONE};
        uint256 marker_token;

        friend bool operator==(const HistoricalAdmissionContext&,
                               const HistoricalAdmissionContext&) = default;
    };

    enum class HistoricalRosterAuthorization : uint8_t {
        INVALID = 0,
        EXACT_NETWORK,
    };

    struct PendingPaymentAuditReceiptDependency {
        pq::PaymentAuditReceipt receipt;
        uint256 carrier_hash;
        uint256 carrier_parent_hash;

        friend bool operator==(
            const PendingPaymentAuditReceiptDependency&,
            const PendingPaymentAuditReceiptDependency&) = default;
    };

    struct PaymentAuditHistoricalContext {
        PendingPaymentAuditReceiptDependency dependency;
        uint256 best_candidate_hash;
        int32_t best_candidate_height{-1};

        friend bool operator==(const PaymentAuditHistoricalContext&,
                               const PaymentAuditHistoricalContext&) = default;
    };

    struct RuntimeVerificationContext {
        pq::PreparedChainLockContextPtr prepared_context;
        HistoricalAdmissionContext historical;
        uint64_t roster_source_generation{0};
    };

    struct PendingVerifiedHistoricalChainLock {
        pq::FinalChainLock chainlock;
        RuntimeVerificationContext verification;
        uint256 logical_id;
        uint256 witness_id;
    };

    struct CurrentSigningContext {
        uint8_t variant_index{0};
        pq::ChainLockStatement statement;
        pq::FrozenQuorumRostersPtr rosters;
        uint8_t authorization_mask{0};
    };

    struct CurrentSigningSource {
        uint64_t admission_generation{0};
        uint64_t finality_store_revision{0};
        uint64_t roster_source_generation{0};
        uint64_t persistence_certificate_revision{0};
        uint64_t provenance_revocation_revision{0};
        uint256 mutable_signing_context_token;
        pq::ChainLockPredecessor durable_predecessor;
        pq::ChainLockSigningWindow window;
        uint256 target_hash;
        uint256 declared_predecessor_hash;
        uint256 payment_audit_preseal_token;
        pq::BTCCReceiptState btcc_receipt_state;
        pq::PaymentAuditReceiptState payment_audit_receipt_state;
        uint256 payment_probation_state_hash;
        bool staged_recovery{false};

        friend bool operator==(const CurrentSigningSource&,
                               const CurrentSigningSource&) = default;
    };

    /**
     * Process-local proof of one fully checked active-chain suffix. A verified
     * non-null carrier remains proven if its certificate leaves the bounded
     * store: accepted certificates and this handler's config are immutable.
     * Stop, branch changes, and provenance revocation discard the proof.
     */
    struct LiveSigningValidationFrontier {
        bool initialized{false};
        uint64_t provenance_revocation_revision{0};
        pq::ChainLockPredecessor durable_predecessor;
        int32_t validated_through_height{-1};
        uint256 validated_through_hash;
    };

    struct BTCCReceiptRecomputeFrontier {
        bool initialized{false};
        uint256 context_token;
        uint64_t provenance_revocation_revision{0};
        int32_t target_height{-1};
        uint256 target_hash;
        int32_t first_carrier_height{-1};
        int64_t next_carrier_height{-1};
        pq::BTCCReceiptState initial_state;
        pq::BTCCReceiptState state;
    };

    struct BTCCPresealRecoveryRuntime {
        BoundedActiveRangeFrontier frontier;
        std::optional<pq::BTCCPresealMarker> recovered;
    };

    enum class PaymentAuditGCMaintenancePhase : uint8_t {
        NONE = 0,
        ARCHIVE,
        PROBATION,
        INVALID,
    };

    struct PaymentAuditGCMaintenancePlan {
        PaymentAuditGCMaintenancePhase phase{
            PaymentAuditGCMaintenancePhase::NONE};
        pq::PaymentAuditStoreCheckpoint checkpoint;
        std::vector<uint256> retained_probation_roots;
        bool derive_retained_probation_roots{false};
    };

    enum class BTCCReplayCarrierStatus : uint8_t {
        VERIFIED = 0,
        MISSING,
        INVALID,
        LOCAL_ERROR,
    };

    struct BTCCReplayCarrierCheck {
        BTCCReplayCarrierStatus status{
            BTCCReplayCarrierStatus::LOCAL_ERROR};
        uint256 logical_id;
    };

    struct BTCCReplayValidationStep {
        std::optional<int32_t> validated_through;
        std::optional<uint256> missing_logical_id;
        BTCCReplayCarrierStatus terminal_status{
            BTCCReplayCarrierStatus::VERIFIED};
        int32_t blocked_carrier_height{-1};
        uint256 blocked_carrier_hash;
        uint256 blocked_logical_id;
    };

    enum class NeededBTCCCertificateSource : uint8_t {
        LIVE_FRONTIER = 0,
        PRESEAL_REPLAY = 1,
    };

    struct NeededBTCCCertificate {
        NeededBTCCCertificateSource source{
            NeededBTCCCertificateSource::LIVE_FRONTIER};
        uint256 logical_id;
        uint256 source_token;
        std::chrono::microseconds last_request{0};
    };

    struct PendingBTCCReceiptDependency {
        uint256 logical_id{};
        uint256 carrier_hash{};

        friend bool operator==(const PendingBTCCReceiptDependency&,
                               const PendingBTCCReceiptDependency&) = default;
    };

    enum class BTCCReceiptArchiveSource : uint8_t {
        PENDING_CARRIER = 0,
        LIVE_FRONTIER,
        PRESEAL_REPLAY,
    };

    /** Immutable admission capability retained across the WOTS+ checks. */
    struct BTCCReceiptArchiveCapability {
        BTCCReceiptArchiveSource source{
            BTCCReceiptArchiveSource::PENDING_CARRIER};
        uint256 logical_id;
        uint256 source_token;
        uint64_t persistence_certificate_revision{0};
        pq::ReceiptArchiveRosterAuthorization authorization;

        friend bool operator==(const BTCCReceiptArchiveCapability&,
                               const BTCCReceiptArchiveCapability&) = default;
    };

    struct CurrentSigningContexts {
        static constexpr std::size_t MAX_VARIANTS{2};

        CurrentSigningSource source;
        std::array<pq::ChainLockStatement, MAX_VARIANTS> statements{};
        std::array<pq::PreparedChainLockContextPtr, MAX_VARIANTS>
            prepared_contexts{};
        std::size_t count{0};
        pq::VerifiedRosterSetPtr roster_set;
        std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;

        [[nodiscard]] std::optional<CurrentSigningContext> Find(
            const pq::ChainLockStatement& statement) const;
    };

    using CurrentSigningContextsPtr =
        std::shared_ptr<const CurrentSigningContexts>;

    // Message and scheduler threads have deliberately small stacks. The
    // statements carry the bounded roster-beacon authorization state, while
    // the much larger immutable roster set remains shared by pointer.
    static_assert(sizeof(RuntimeVerificationContext) <= 64);
    static_assert(sizeof(CurrentSigningContext) <= 1696);
    static_assert(sizeof(CurrentSigningContexts) <= 3960);

    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    PrepareCandidate(
        const pq::ChainLockCandidateContextRequest& request) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    RecheckCandidate(
        const pq::ChainLockCandidateContextRequest& request,
        const pq::ChainLockCandidateContext& prepared) const override
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] pq::AcceptedBranchRelation QueryAcceptedBranch(
        int32_t height,
        const uint256& block_hash,
        int32_t accepted_tip_height,
        const uint256& accepted_tip_hash) const override;

    // SYSCOIN: A declared predecessor is not a local validation checkpoint
    // until at least one fully verified winner has been made durable.
    [[nodiscard]] static int32_t CandidateFullValidationFloor(
        const pq::ChainLockCandidateContextRequest& request,
        int32_t activation_predecessor_height) noexcept;
    [[nodiscard]] static HistoricalIndexValidationMode
    CandidateTargetValidationMode(
        pq::ChainLockCandidateAdmission admission) noexcept;
    [[nodiscard]] static bool IsCandidateTargetValidationSufficient(
        pq::ChainLockCandidateAdmission admission,
        bool has_local_chainlock,
        bool marker_authorized_catchup,
        bool exact_local_target,
        bool historical_receipt_range_ready) noexcept;
    [[nodiscard]] std::optional<pq::ChainLockCandidateContext>
    BuildCandidateContext(
        const pq::ChainLockCandidateContextRequest& request,
        const CBlockIndex** candidate = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] PaymentAuditContextStatus
    ClassifyHistoricalReceiptIndexRangeCached(
        const CBlockIndex& last, int32_t first_height) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool HasChainLockTargetValidationCached(
        const CBlockIndex& candidate, int32_t predecessor_height,
        HistoricalIndexValidationMode mode) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] BTCCCatchupRangeStatus
    GetFullyValidatedBTCCCatchupRangeStatusCached(
        const CBlockIndex& candidate,
        const pq::BTCCReceiptAssumptionAnchor& anchor) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] PaymentAuditContextStatus
    ClassifyPaymentAuditSealContextCached(
        const CBlockIndex* seal, int32_t expected_height,
        int32_t predecessor_height, const uint256& predecessor_hash,
        PaymentAuditSealValidation validation) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] std::optional<pq::BTCCReceiptState>
    RecomputeBTCCReceiptStateCached(
        const CBlockIndex& target,
        int32_t first_carrier_height,
        const pq::BTCCReceiptState& initial_state,
        const uint256& context_token,
        bool* transient_failure = nullptr,
        std::size_t* examined_carriers = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool RecoverActiveBTCCPresealBounded(
        const CBlockIndex& active_tip,
        pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] std::optional<int32_t>
    AdvanceBTCCReplayValidationBounded(
        const CBlockIndex& active_tip,
        const pq::BTCCPresealState& state,
        int32_t authenticated_through)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] static BTCCReplayValidationStep
    AdvanceBTCCReplayValidationFrontier(
        BoundedActiveRangeFrontier& frontier,
        const CChain& active_chain,
        const CBlockIndex& active_tip,
        int32_t authenticated_through,
        const uint256& authenticated_hash,
        const uint256& source_token,
        const pq::BTCCScheduleConfig& schedule,
        const std::function<BTCCReplayCarrierCheck(
            const CBlockIndex&)>& check,
        std::size_t block_budget =
            HistoricalIndexValidationCache::BLOCK_BUDGET)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] std::optional<pq::BTCCReceiptState>
    GetCatchupHistoricalProof(const CBlockIndex& candidate,
                              HistoricalAdmission admission) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_btcc_preseal_mutex);
    [[nodiscard]] std::optional<RuntimeVerificationContext>
    BuildRuntimeVerificationContext(
        const pq::PreparedFinalChainLockCandidate& prepared,
        bool* definitively_invalid = nullptr,
        bool publish_roster = false,
        const BTCCReceiptArchiveCapability*
            receipt_archive_capability = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    enum class RosterBeaconEvidence : uint8_t {
        SIGNER_POLICY,
        THRESHOLD_CERTIFICATE,
    };
    [[nodiscard]] std::optional<pq::NormalRosterAuthorizationInput>
    BuildNormalRosterAuthorizationInput(
        const pq::ChainLockStatement& statement,
        const pq::FinalChainLockRecordMetadata& prior,
        pq::RosterAuthorizationTransitionKind requested_transition,
        RosterBeaconEvidence evidence) const;
    [[nodiscard]] std::optional<
        pq::RosterAuthorizationVerificationContext>
    BuildNetworkRosterAuthorizationContext(
        const pq::ChainLockStatement& statement,
        const CBlockIndex& candidate,
        const pq::FinalChainLockRecordMetadata* prior) const;
    [[nodiscard]] pq::RecoveryRosterAuthorityPtr
    DeriveRecoveryRosterAuthority(
        pq::RosterAuthorizationTransitionKind transition,
        const CBlockIndex& candidate,
        const pq::FinalChainLockRecordMetadata* prior,
        const pq::FrozenQuorumRosterCachePtr& roster_cache,
        pq::RecoveryRosterAuthoritySource* source_out = nullptr,
        pq::QuorumBuildError* error = nullptr) const;
    [[nodiscard]] pq::RecoveryRosterAuthorityPtr
    ResolveRecoveryRosterAuthority(
        const pq::ChainLockStatement& statement,
        const CBlockIndex& candidate,
        const pq::FinalChainLockRecordMetadata* prior,
        const pq::FrozenQuorumRosterCachePtr& roster_cache,
        pq::QuorumBuildError* error = nullptr) const;
    [[nodiscard]] std::optional<RuntimeVerificationContext>
    BuildHistoricalPreVerificationContext(
        const pq::FinalChainLock& chainlock,
        const HistoricalAdmissionContext& expected,
        const BTCCReceiptArchiveCapability*
            receipt_archive_capability = nullptr,
        bool* definitively_invalid = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex);
    [[nodiscard]] static HistoricalRosterAuthorization
    SelectHistoricalRosterAuthorization(
        pq::ChainLockCandidateAdmission candidate_admission,
        HistoricalAdmission historical_admission,
        pq::RosterAuthorizationTransitionKind transition) noexcept;
    [[nodiscard]] static pq::ChainLockCandidateAdmission
    SelectHistoricalPreVerificationAdmission(
        HistoricalAdmission historical_admission,
        int32_t statement_height,
        std::optional<int32_t> best_height) noexcept;
    [[nodiscard]] static bool IsHistoricalArchiveIdentity(
        pq::ChainLockCandidateAdmission candidate_admission) noexcept;
    [[nodiscard]] bool IsHistoricalVerificationCapabilityCurrent(
        const RuntimeVerificationContext& verification,
        const HistoricalAdmissionContext& expected) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] static bool DoesHistoricalVerificationCapabilityMatch(
        const HistoricalAdmissionContext& verified,
        uint64_t verified_roster_generation,
        const HistoricalAdmissionContext& expected,
        uint64_t current_roster_generation) noexcept;
    [[nodiscard]] std::shared_ptr<const PendingVerifiedHistoricalChainLock>
    GetPendingVerifiedHistoricalChainLock() const;
    [[nodiscard]] bool RetainVerifiedHistoricalChainLock(
        const pq::FinalChainLock& chainlock,
        const RuntimeVerificationContext& verification);
    void ContinueVerifiedHistoricalChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);
    [[nodiscard]] bool IsConfiguredForVerification() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] pq::FrozenQuorumRosterCachePtr GetQuorumRosterCache(
        uint64_t* generation = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] bool IsQuorumRosterSourceGenerationCurrent(
        uint64_t generation) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] bool RevokeAuxiliaryHistoryGCAuthorization();
    void DisableShareAdmission() noexcept;
    [[nodiscard]] uint64_t GetShareAdmissionGeneration() const noexcept;
    [[nodiscard]] bool IsShareAdmissionGenerationCurrent(
        uint64_t generation) const noexcept;
    [[nodiscard]] bool IsChainLockVerificationAvailable() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex);
    [[nodiscard]] bool ReconcileSignerJournal(const uint256& pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(!m_signer_reconcile_mutex);
    [[nodiscard]] bool InitializeSignerStartupTip(
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex, !cs_main);
    [[nodiscard]] bool ConsumeStartupChainLockSlots(
        const pq::PreparedChainLockContext& context,
        const CurrentSigningSource& source,
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex);
    [[nodiscard]] bool ConsumeStartupPaymentAuditSlots(
        const pq::PreparedPaymentAuditContext& context,
        const uint256& local_pro_tx_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_signing_mutex);
    void MaybeCreateAndSignChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_share_signing_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_btc_header_policy_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex);
    struct LocalChainLockFinalization {
        pq::CollectedChainLockFinalizationPtr proof;
        CurrentSigningContextsPtr signing_contexts;
        std::size_t variant_index{0};
        uint64_t admission_generation{0};
        uint64_t collector_generation{0};
    };
    struct ChainLockShareCollectionOutcome {
        pq::ShareCollectionResult result{
            pq::ShareCollectionResult::REJECTED};
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        std::optional<LocalChainLockFinalization> finalized;
        uint64_t collector_generation{0};
        bool stale{false};
    };
    [[nodiscard]] bool ProcessCollectedChainLock(
        const LocalChainLockFinalization& finalized,
        BlockValidationState& state)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_lifecycle_mutex,
                                 !cs_main,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);
    [[nodiscard]] bool ProcessNewChainLockInternal(
        NodeId from,
        const pq::FinalChainLock& chainlock,
        BlockValidationState& state,
        bool* peer_fault,
        const LocalChainLockFinalization* local_finalization,
        const PendingVerifiedHistoricalChainLock* continuation = nullptr,
        bool* retain_continuation = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);
    [[nodiscard]] ChainLockShareCollectionOutcome CollectChainLockShare(
        const pq::ChainLockShare& share,
        CurrentSigningContextsPtr signing_contexts,
        std::size_t variant_index,
        uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex);
    void ProcessChainLockShare(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_signer_reconcile_mutex);
    void ProcessPaymentAuditCertificate(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    struct LocalPaymentAuditFinalization {
        pq::CollectedPaymentAuditFinalizationPtr proof;
        uint64_t admission_generation{0};
        uint64_t runtime_generation{0};
        uint64_t roster_source_generation{0};
    };
    struct PaymentAuditRemoteRequestContext {
        std::optional<uint256> requested;
        bool may_be_cancelled_response{false};
        bool required_response{false};
    };
    void ProcessCollectedPaymentAudit(
        const LocalPaymentAuditFinalization& finalized)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_lifecycle_mutex,
                                 !cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void ProcessPaymentAuditCertificateInternal(
        CNode* from,
        const pq::FinalPaymentAudit& audit,
        const PaymentAuditRemoteRequestContext& remote,
        const LocalPaymentAuditFinalization* local_finalization)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void FinishPaymentAuditFinalizationAttempt(
        const LocalPaymentAuditFinalization& finalized)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex);
    void SubmitPaymentAuditFinalizationAttempt(
        const LocalPaymentAuditFinalization& finalized)
        EXCLUSIVE_LOCKS_REQUIRED(m_share_lifecycle_mutex,
                                 !cs_main,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    enum class PaymentAuditRosterBuildStatus : uint8_t {
        VALID = 0,
        INVALID,
        LOCAL_ERROR,
    };
    [[nodiscard]] pq::VerifiedRosterSetPtr
    BuildPaymentAuditVerificationRosters(
        const pq::PaymentAuditStatement& statement,
        pq::FrozenQuorumRoster* subject = nullptr,
        pq::RosterAuthorizationVerificationContext* authorization = nullptr,
        bool require_live_transition_finality = false,
        PaymentAuditRosterBuildStatus* status = nullptr,
        const PaymentAuditHistoricalContext* historical = nullptr,
        uint64_t* roster_source_generation = nullptr,
        int32_t* reconstruction_floor = nullptr,
        bool defer_historical_provenance = false) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex);
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    BuildStoredVerifiedPaymentAuditSubject(
        const pq::StoredVerifiedPaymentAudit& stored,
        const CBlockIndex& carrier_parent,
        int32_t carrier_height,
        pq::FrozenQuorumRoster& subject,
        uint64_t& roster_source_generation,
        int32_t& reconstruction_floor) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_lookup_mutex);
    [[nodiscard]] PaymentAuditReceiptCertificateStatus
    RecheckVerifiedPaymentAuditReceiptTransition(
        const VerifiedPaymentAuditReceiptTransition& verified,
        const pq::PaymentAuditReceipt& receipt,
        const CBlockIndex& carrier) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_lookup_mutex);
    [[nodiscard]] std::optional<PaymentAuditHistoricalContext>
    ResolvePendingPaymentAuditContext(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool RetireInvalidPendingPaymentAuditReceipt(
        const PaymentAuditHistoricalContext& expected)
        EXCLUSIVE_LOCKS_REQUIRED(
            !cs_main, !m_pending_payment_audit_receipt_mutex);
    void ProcessPaymentAuditHave(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void ProcessPaymentAuditResponse(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_share_lifecycle_mutex);
    struct PaymentAuditShareCollectionOutcome {
        pq::ShareCollectionResult result{
            pq::ShareCollectionResult::REJECTED};
        pq::ShareCollectionError error{pq::ShareCollectionError::NONE};
        std::optional<LocalPaymentAuditFinalization> finalized;
        bool stale{false};
        bool closed{false};
        bool accepted_duplicate{false};
    };
    [[nodiscard]] PaymentAuditShareCollectionOutcome
    CollectPaymentAuditShare(
        const pq::PaymentAuditShare& share,
        const pq::PaymentAuditStatement& statement,
        uint64_t admission_generation,
        uint64_t expected_runtime_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void ProcessPaymentAuditShare(CNode* from, CDataStream& payload)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_verification_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeCapturePaymentAuditResponse(
        const pq::ChainLockShare& share,
        const pq::FrozenQuorumRostersPtr& rosters,
        uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void RelayPaymentAuditResponse(
        const pq::PaymentAuditResponse& response,
        NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeRelayPaymentAuditHave()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    void RelayPaymentAuditShare(
        const pq::PaymentAuditShare& share,
        const pq::PreparedPaymentAuditContextPtr& prepared_context,
        const std::shared_ptr<const ChainLockRelayRecipients>& recipients,
        uint64_t runtime_generation,
        uint64_t admission_generation,
        NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool HasExactPaymentAuditRuntime(
        uint64_t expected_runtime_generation,
        const pq::PaymentAuditStatement& statement,
        const pq::PreparedPaymentAuditContextPtr& prepared_context,
        const std::shared_ptr<const ChainLockRelayRecipients>& recipients)
        const EXCLUSIVE_LOCKS_REQUIRED(!m_payment_audit_mutex);
    [[nodiscard]] bool HasExactPaymentAuditFinalization(
        const LocalPaymentAuditFinalization& finalized) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_payment_audit_mutex);
    [[nodiscard]] bool PreparePaymentAuditSigningRuntime()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsCurrentPaymentAuditStatement(
        const pq::PaymentAuditStatement& statement) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void MaybeCreateAndSignPaymentAudit()
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_share_lifecycle_mutex,
                                 !m_payment_audit_mutex,
                                 !m_lookup_mutex,
                                 !m_verification_mutex,
                                 !m_share_signing_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_payment_audit_receipt_mutex,
                                 !m_btcc_preseal_mutex,
                                 !m_btc_header_policy_mutex);

    struct PaymentAuditResponseDefinition {
        pq::PaymentAuditOpenRowMetadata row;
        pq::PreparedChainLockContextPtr response_context;
        std::vector<uint256> active_relays;
    };
    struct PaymentAuditNetworkContext {
        std::vector<PaymentAuditResponseDefinition> rows;
    };
    struct PaymentAuditResponseRuntime {
        pq::PaymentAuditRound round;
        pq::PaymentAuditFrozenRowSummary selected_row;
        std::optional<pq::PaymentAuditStatement> statement;
        std::optional<pq::FinalChainLock> seal_chainlock;
        pq::FrozenQuorumRostersPtr signing_rosters;
        std::shared_ptr<const ChainLockRelayRecipients> relay_recipients;
        uint8_t authorization_mask{0};
        uint64_t roster_source_generation{0};
        std::unique_ptr<pq::PaymentAuditCollector> collector;
        std::optional<LocalPaymentAuditFinalization> finalized;
        std::optional<std::chrono::microseconds> finalization_last_attempt;
        bool finalization_attempt_in_flight{false};
        bool local_signing_complete{false};
    };
    void ResetPaymentAuditRuntime()
        EXCLUSIVE_LOCKS_REQUIRED(m_payment_audit_mutex);
    [[nodiscard]] uint64_t PublishPaymentAuditRuntime(
        PaymentAuditResponseRuntime runtime)
        EXCLUSIVE_LOCKS_REQUIRED(m_payment_audit_mutex);
    [[nodiscard]] std::optional<PaymentAuditResponseDefinition>
    BuildPaymentAuditResponseDefinition(uint32_t epoch,
                                        uint8_t row_index) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPaymentAuditResponseDefinitionSourceCurrent(
        const PaymentAuditResponseDefinition& definition) const;
    [[nodiscard]] bool RefreshPaymentAuditNetworkContext()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] std::shared_ptr<const PaymentAuditNetworkContext>
    GetPaymentAuditNetworkContext() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_payment_audit_mutex);
    [[nodiscard]] bool IsCurrentPaymentAuditNetworkRow(
        const pq::PaymentAuditOpenRowMetadata& row) const
        EXCLUSIVE_LOCKS_REQUIRED(!cs_main,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool RefreshPaymentAuditStaging()
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_payment_audit_mutex,
                                 !m_btcc_preseal_mutex);
    /** Build the exact live capability; only the private scheduler calls it. */
    [[nodiscard]] std::optional<CurrentSigningContexts>
    BuildCurrentSigningContexts(uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(m_context_build_mutex,
                                 !m_lookup_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    /**
     * Extend a private proof over the active suffix. The certificate callback
     * is production-owned; tests can inject only through the private friend.
     */
    [[nodiscard]] static bool AdvanceLiveSigningValidationFrontier(
        LiveSigningValidationFrontier& frontier,
        const CChain& active_chain,
        const CBlockIndex& target,
        const pq::ChainLockPredecessor& durable_predecessor,
        const pq::ChainLockFinalityStoreConfig& config,
        const uint256& genesis_hash,
        uint64_t provenance_revocation_revision,
        const std::function<BTCCReceiptCertificateStatus(
            const pq::BTCCReceipt&, const CBlockIndex&)>&
            certificate_status,
        uint64_t& examined_blocks,
        std::size_t block_budget =
            HistoricalIndexValidationCache::BLOCK_BUDGET)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] static bool IsLiveSigningValidationRevisionCurrent(
        const CurrentSigningSource& source,
        uint64_t provenance_revocation_revision) noexcept;
    [[nodiscard]] static bool HasExactLiveSigningTargetEndpoint(
        const CBlockIndex& target)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool RefreshCurrentSigningContexts(
        uint64_t admission_generation)
        EXCLUSIVE_LOCKS_REQUIRED(!m_context_build_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    /**
     * Return only an already-published capability. This path deliberately
     * performs no chain suffix, receipt, roster, or collector construction.
     */
    [[nodiscard]] CurrentSigningContextsPtr
    GetPublishedCurrentSigningContexts(uint64_t admission_generation) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_collector_mutex);
    /**
     * Recheck mutable inputs without reminting the private capability. This
     * does not prove that its historical suffix was validated; only the
     * scheduler-owned builder may establish that invariant.
     */
    [[nodiscard]] bool IsCurrentSigningSource(
        const CurrentSigningSource& source) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool CheckBTCHeaderSigningPolicy(
        const pq::ChainLockStatement& statement)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btc_header_policy_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool CheckPaymentAuditSeedSigningPolicy(
        const pq::PaymentAuditStatement& statement)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btc_header_policy_mutex,
                                 !m_payment_audit_mutex);
    void RequestNeededBTCCCertificate()
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    void NoteNeededBTCCCertificate(
        NeededBTCCCertificateSource source,
        const uint256& logical_id,
        const uint256& source_token)
        EXCLUSIVE_LOCKS_REQUIRED(!m_needed_btcc_certificate_mutex);
    void ClearNeededBTCCCertificate(
        NeededBTCCCertificateSource source,
        const std::optional<uint256>& source_token = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(!m_needed_btcc_certificate_mutex);
    void ClearNeededBTCCCertificate(const uint256& logical_id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_needed_btcc_certificate_mutex);
    [[nodiscard]] bool IsNeededBTCCReceiptCertificate(
        const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] std::optional<BTCCReceiptArchiveCapability>
    GetBTCCReceiptArchiveCapability(const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] bool IsBTCCReceiptArchiveCapabilityCurrent(
        const BTCCReceiptArchiveCapability& capability) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] static bool DoesBTCCReceiptArchiveSourceMatch(
        const BTCCReceiptArchiveCapability& capability,
        const std::optional<PendingBTCCReceiptDependency>& pending,
        const std::optional<NeededBTCCCertificate>& needed) noexcept;
    [[nodiscard]] bool AuthorizeBTCCReceiptArchivePersistence(
        const BTCCReceiptArchiveCapability& capability,
        const std::function<bool()>& persist_record,
        pq::ChainLockFinalityError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] std::optional<pq::ReceiptArchiveRosterAuthorization>
    GetReceiptArchiveCoverageAuthorization(
        const pq::PreparedFinalChainLockCandidate& prepared) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] static bool PublishNeededBTCCCertificate(
        std::optional<NeededBTCCCertificate>& current,
        NeededBTCCCertificateSource source,
        const uint256& logical_id,
        const uint256& source_token);
    [[nodiscard]] static bool EraseNeededBTCCCertificate(
        std::optional<NeededBTCCCertificate>& current,
        NeededBTCCCertificateSource source,
        const std::optional<uint256>& source_token = std::nullopt);
    [[nodiscard]] static std::optional<uint256>
    SelectRequiredBTCCCertificate(
        const std::optional<uint256>& pending,
        const std::optional<NeededBTCCCertificate>& needed);
    [[nodiscard]] bool RevalidatePendingBTCCReceiptDependency()
        EXCLUSIVE_LOCKS_REQUIRED(!m_pending_btcc_receipt_mutex);
    void RetryPendingBTCCBlock();
    void RequestNeededPaymentAuditCertificate()
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex,
            !m_btcc_preseal_mutex);
    [[nodiscard]] bool RevalidatePendingPaymentAuditReceiptDependency()
        EXCLUSIVE_LOCKS_REQUIRED(
            !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] bool RevalidatePendingPaymentAuditReceiptDependencyLocked()
        EXCLUSIVE_LOCKS_REQUIRED(
            cs_main, !m_pending_payment_audit_receipt_mutex);
    [[nodiscard]] HistoricalAdmissionContext
    GetHistoricalAdmission(const pq::ChainLockStatement& statement,
                           const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] HistoricalAdmissionContext
    GetHistoricalAdmissionLocked(const pq::ChainLockStatement& statement,
                                 const uint256& logical_id) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void RequestCatchupChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_catchup_mutex,
                                 !m_btcc_preseal_mutex);
    void MaybeReplayBTCCPreseal()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex);
    void MaybeReplayPaymentAuditPreseal()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool ClearBTCCPreseal(
        const pq::BTCCPresealMarker& expected)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] bool PersistBTCCPresealStateLocked(
        const pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex,
                                 !m_needed_btcc_certificate_mutex);
    [[nodiscard]] bool PersistPaymentAuditPresealStateLocked(
        const pq::PaymentAuditPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_btcc_preseal_mutex);
    [[nodiscard]] bool FlushPaymentAuditPresealBlockFilesForDurability(
        const pq::PaymentAuditPresealState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    [[nodiscard]] bool ClearPaymentAuditPreseal(
        const pq::PaymentAuditPresealMarker& expected)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void UpdateBTCCPresealPruneLock(const pq::BTCCPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void UpdatePaymentAuditPresealPruneLock(
        const pq::PaymentAuditPresealState& state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void UpdatePresealAuxiliaryRetention(
        const pq::BTCCPresealState& btcc_state,
        const pq::PaymentAuditPresealState& payment_audit_state)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void MaybeCheckpointPaymentAuditPreseal(
        const pq::FinalChainLockRecordMetadata& durable_winner)
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    void MaintainPaymentAuditCheckpointGC()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] bool ContinuePaymentAuditCheckpointGC()
        EXCLUSIVE_LOCKS_REQUIRED(!m_btcc_preseal_mutex);
    [[nodiscard]] static PaymentAuditGCMaintenancePlan
    SelectPaymentAuditGCMaintenancePlan(
        const std::optional<pq::PaymentAuditStoreCheckpoint>&
            pending_archive,
        const std::optional<pq::PaymentAuditStoreCheckpoint>&
            pending_probation,
        std::span<const uint256> pending_probation_roots,
        const std::optional<pq::PaymentAuditStoreCheckpoint>&
            completed_archive,
        bool completed_probation) noexcept;
    void UpdateDurableChainLockAuxiliaryRetention();
    [[nodiscard]] bool FlushChainLockAuxiliarySnapshotsForDurability();
    void MaybeReleaseFinalitySnapshotPublicationRetention()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    /**
     * Fsync branch-derived BTCPREV and receipt index metadata before the
     * corresponding live/catch-up certificate can become durable.
     */
    [[nodiscard]] bool FlushBTCCIndexStateForDurableAcceptance(
        const pq::FinalChainLock& chainlock) const LOCKS_EXCLUDED(cs_main);
    void RelayChainLockShare(const pq::ChainLockShare& share,
                             CurrentSigningContextsPtr signing_contexts,
                             std::size_t variant_index,
                             uint64_t admission_generation,
                             NodeId except_peer = -1)
        EXCLUSIVE_LOCKS_REQUIRED(!m_share_lifecycle_mutex,
                                 !m_collector_mutex,
                                 !m_lookup_mutex,
                                 !m_btcc_preseal_mutex);
    void ResetCollectors() EXCLUSIVE_LOCKS_REQUIRED(m_collector_mutex);
    enum class PersistedChainLockImport : uint8_t {
        NONE = 0,
        PENDING,
        ACCEPTED,
        INVALID,
    };
    [[nodiscard]] PersistedChainLockImport TryImportPersistedChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_signer_reconcile_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] PersistedChainLockImport TryImportPersistedUnsealedBTCC()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_lookup_mutex,
                                 !m_chainlock_admission_mutex,
                                 !m_verification_mutex,
                                 !m_collector_mutex,
                                 !m_pending_btcc_receipt_mutex,
                                 !m_needed_btcc_certificate_mutex,
                                 !m_btcc_preseal_mutex);
    [[nodiscard]] bool IsPersistedChainLockPending() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    [[nodiscard]] bool HasPendingPQHistoryAuthentication() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_main,
                                 !m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void RefreshPQHistoryAuthState()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void QuarantineInvalidPersistedChainLock(const std::string& reason)
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex);
    void EnforceBestChainLock()
        EXCLUSIVE_LOCKS_REQUIRED(!m_persisted_mutex,
                                 !m_btcc_preseal_mutex);
    void CompletePeerResponse(NodeId from, const uint256& logical_id);
    void FailPeerResponse(NodeId from, const uint256& logical_id);
    void ForgetAllRequests(const uint256& logical_id);

    CConnman& m_connman;
    PeerManager& m_peerman;
    ChainstateManager& m_chainman;

    const uint256 m_genesis_hash;
    const std::optional<pq::ChainLockFinalityStoreConfig> m_config;
    const std::optional<pq::QuorumBuildConfig> m_quorum_build_config;
    std::unique_ptr<pq::PQChainLockPersistence> m_persistence;
    std::unique_ptr<pq::ChainLockFinalityStore> m_store;
    std::unique_ptr<pq::PaymentAuditStore> m_payment_audit_store;
    std::unique_ptr<pq::PaymentAuditStagingStore>
        m_payment_audit_staging_store;
    mutable PaymentAuditCandidateMetadataCache
        m_payment_audit_candidate_metadata_cache;
    mutable PaymentAuditReceiptCache m_payment_audit_receipt_cache;
    mutable std::unique_ptr<VerifiedPaymentAuditReceiptTransitionCache>
        m_verified_payment_audit_transition_cache;
    mutable pq::ChainLockVerifier m_verifier;
    mutable pq::CatchupHistoricalProofCache m_catchup_proof_cache;

    mutable Mutex m_lookup_mutex;
    pq::FrozenQuorumRosterCachePtr m_quorum_roster_cache
        GUARDED_BY(m_lookup_mutex);
    uint64_t m_quorum_roster_source_generation
        GUARDED_BY(m_lookup_mutex){0};
    // ChainLock admission may rebuild branch context and therefore acquire
    // cs_main. Keep that serialization independent from the crypto-only mutex
    // so ConnectBlock can verify an archived audit while holding cs_main.
    mutable Mutex m_chainlock_admission_mutex;
    mutable Mutex m_verification_mutex;
    mutable Mutex m_persisted_mutex;
    std::optional<pq::FinalChainLock> m_pending_persisted
        GUARDED_BY(m_persisted_mutex);
    std::optional<pq::FinalChainLock> m_pending_persisted_unsealed_btcc
        GUARDED_BY(m_persisted_mutex);
    // Exact witness which was fully reverified through the bounded
    // historical-governance path in this process. It is never a height-only
    // authorization and is reset when a different winner is accepted.
    uint256 m_threshold_attested_enforcement_witness
        GUARDED_BY(m_persisted_mutex);
    bool m_persisted_invalid GUARDED_BY(m_persisted_mutex){false};
    // A loaded best record remains an authentication obligation after its
    // in-memory import pointer is cleared, until active-chain enforcement has
    // completed. Otherwise an unrelated marker refresh could publish READY in
    // the import/enforcement gap.
    bool m_persisted_best_auth_pending GUARDED_BY(m_persisted_mutex){false};
    bool m_persisted_unsealed_auth_pending
        GUARDED_BY(m_persisted_mutex){false};

    mutable Mutex m_collector_mutex;
    std::array<std::unique_ptr<pq::ChainLockCollector>,
               CurrentSigningContexts::MAX_VARIANTS> m_collectors
        GUARDED_BY(m_collector_mutex);
    CurrentSigningContextsPtr m_current_signing_contexts
        GUARDED_BY(m_collector_mutex);
    uint64_t m_collector_generation GUARDED_BY(m_collector_mutex){0};
    Mutex m_context_build_mutex;
    LiveSigningValidationFrontier m_live_signing_validation_frontier
        GUARDED_BY(m_context_build_mutex);
    uint64_t m_live_signing_validation_examined_blocks
        GUARDED_BY(m_context_build_mutex){0};
    mutable HistoricalIndexValidationCache
        m_historical_index_validation_cache GUARDED_BY(cs_main);
    mutable BTCCReceiptRecomputeFrontier
        m_btcc_receipt_recompute_frontier GUARDED_BY(cs_main);
    BTCCPresealRecoveryRuntime m_btcc_preseal_recovery_runtime
        GUARDED_BY(cs_main);
    BoundedActiveRangeFrontier m_btcc_replay_validation_frontier
        GUARDED_BY(cs_main);
    mutable std::shared_ptr<const PendingVerifiedHistoricalChainLock>
        m_pending_verified_historical;
    std::unique_ptr<CPQSignerJournal> m_signer_journal;
    Mutex m_signer_reconcile_mutex;
    Mutex m_share_signing_mutex;
    uint256 m_signer_startup_pro_tx_hash GUARDED_BY(m_share_signing_mutex);
    std::optional<int32_t> m_signer_startup_tip_height
        GUARDED_BY(m_share_signing_mutex);
    mutable Mutex m_payment_audit_mutex;
    std::optional<PaymentAuditResponseRuntime> m_payment_audit_runtime
        GUARDED_BY(m_payment_audit_mutex);
    uint64_t m_payment_audit_runtime_generation
        GUARDED_BY(m_payment_audit_mutex){0};
    std::shared_ptr<const PaymentAuditNetworkContext>
        m_payment_audit_network_context GUARDED_BY(m_payment_audit_mutex);
    std::map<uint256, std::map<uint256, pq::QuorumBitmap>>
        m_payment_audit_supplied_to_peer GUARDED_BY(m_payment_audit_mutex);
    Mutex m_btc_header_policy_mutex;
    std::optional<uint256> m_btc_header_policy_last_denied
        GUARDED_BY(m_btc_header_policy_mutex);
    std::string m_btc_header_policy_last_reason
        GUARDED_BY(m_btc_header_policy_mutex);
    mutable Mutex m_needed_btcc_certificate_mutex;
    mutable std::optional<NeededBTCCCertificate> m_needed_btcc_certificate
        GUARDED_BY(m_needed_btcc_certificate_mutex);

    mutable Mutex m_pending_btcc_receipt_mutex;
    std::optional<PendingBTCCReceiptDependency> m_pending_btcc_receipt
        GUARDED_BY(m_pending_btcc_receipt_mutex);
    std::chrono::microseconds m_pending_btcc_last_request
        GUARDED_BY(m_pending_btcc_receipt_mutex){0};
    std::atomic_bool m_retry_pending_btcc_block{false};
    mutable Mutex m_pending_payment_audit_receipt_mutex;
    std::optional<PendingPaymentAuditReceiptDependency>
        m_pending_payment_audit_receipt
            GUARDED_BY(m_pending_payment_audit_receipt_mutex);
    std::chrono::microseconds m_pending_payment_audit_last_request
        GUARDED_BY(m_pending_payment_audit_receipt_mutex){0};
    mutable Mutex m_catchup_mutex;
    std::chrono::microseconds m_catchup_last_request
        GUARDED_BY(m_catchup_mutex){0};
    std::atomic_bool m_catchup_used{false};
    // SYSCOIN: The scheduler and a just-accepted ChainLock can both enter
    // checkpoint maintenance. Only one may select or advance a durable
    // archive/probation intent at a time; the network path may defer to the
    // next periodic bounded pass instead of waiting on database work.
    std::atomic_bool m_payment_audit_gc_active{false};
    mutable Mutex m_btcc_preseal_mutex;
    pq::BTCCPresealState m_btcc_preseal_state
        GUARDED_BY(m_btcc_preseal_mutex);
    uint64_t m_btcc_preseal_revision GUARDED_BY(m_btcc_preseal_mutex){0};
    pq::PaymentAuditPresealState m_payment_audit_preseal_state
        GUARDED_BY(m_btcc_preseal_mutex);
    uint64_t m_payment_audit_preseal_revision
        GUARDED_BY(m_btcc_preseal_mutex){0};


    mutable Mutex m_lifecycle_mutex;
    std::unique_ptr<CScheduler> m_scheduler GUARDED_BY(m_lifecycle_mutex);
    std::unique_ptr<std::thread> m_scheduler_thread GUARDED_BY(m_lifecycle_mutex);
    bool m_started GUARDED_BY(m_lifecycle_mutex){false};
    // Linearize lifecycle transitions with staging, relay, and local
    // certificate submission; expensive verification uses the generation.
    mutable Mutex m_share_lifecycle_mutex;
    // Lifecycle, operational state, and terminal faults publish atomically so
    // no false->true interval can revive work from an older handler state.
    ShareAdmissionGate m_share_admission_gate;
    AuxiliaryHistoryGCAuthorizationGate m_auxiliary_history_gc_auth_gate;
    std::atomic_bool m_persistence_failed{false};
    std::atomic_bool m_enforced{false};
};

extern CChainLocksHandler* chainLocksHandler;

/** Operational switch for producing new PQ finality material. */
[[nodiscard]] bool AreChainLocksEnabled();

/** Certificate recovery remains available while production is switched off. */
[[nodiscard]] bool ShouldVerifyChainLockCertificate(
    bool configured_and_healthy, bool persisted_import_pending,
    bool persistence_failed) noexcept;

/** Startup import must remain possible while that import holds verification pending. */
[[nodiscard]] bool ShouldAttemptPersistedChainLockImport(
    bool participation_allowed, bool configured_for_verification) noexcept;

/** Startup recovery metadata must remain visible while live service is quarantined. */
[[nodiscard]] bool ShouldExposeDurableFinalityRecoveryMetadata(
    bool configured, bool persistence_available,
    bool persistence_failed) noexcept;

/** Durable Syscoin finality is independent of deferred NEVM replay readiness. */
[[nodiscard]] bool ShouldEnforceDurableChainLock(
    bool configured, bool persisted_import_pending,
    bool btcc_preseal_active) noexcept;

/** Never disconnect the active fork at or below its durable finality floor. */
[[nodiscard]] bool DisconnectCrossesDurableChainLockFloor(
    int32_t disconnect_height, int32_t active_floor_height,
    bool floor_descends_from_disconnect) noexcept;

/** Candidate and durable winner must lie on one ancestry-comparable branch. */
[[nodiscard]] bool IsDurableChainLockCandidateCompatible(
    int32_t candidate_height, int32_t durable_target_height,
    bool candidate_descends_target,
    bool target_descends_candidate) noexcept;

[[nodiscard]] bool IsBTCCPresealCoveredByDurableWinner(
    int32_t marker_height, int32_t winner_height,
    bool winner_descends_marker) noexcept;

/** Immutable archive boundary equality; authorizer refresh fields are ignored. */
[[nodiscard]] bool HasSamePaymentAuditCheckpointBoundary(
    const pq::PaymentAuditStoreCheckpoint& left,
    const pq::PaymentAuditStoreCheckpoint& right) noexcept;

/** Gate the full chainstate durability barrier and both irreversible GCs. */
[[nodiscard]] bool ShouldRunPaymentAuditDurableGC(
    bool reuse_archive_checkpoint,
    bool probation_gc_complete) noexcept;

enum class BTCCCatchupRangeStatus : uint8_t {
    VALID,
    DEFINITIVE_INVALID,
    TRANSIENT_UNAVAILABLE,
};

/**
 * Require the pinned receipt-boundary identity and full subsequent index
 * provenance before historical receipt state may replace block-body replay.
 */
[[nodiscard]] BTCCCatchupRangeStatus
GetFullyValidatedBTCCCatchupRangeStatus(
    const ChainstateManager& chainman,
    const CBlockIndex& candidate,
    const pq::BTCCReceiptAssumptionAnchor& anchor)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** An exact marker receipt newer than local finality becomes the new winner. */
[[nodiscard]] bool ShouldRouteBTCCPresealReceiptToCatchup(
    bool marker_authorized_receipt,
    int32_t receipt_target_height,
    int32_t local_finality_height) noexcept;

/** An exact replay dependency below the winner is archive-only history. */
[[nodiscard]] bool ShouldArchiveRequiredBTCCReceiptCertificate(
    bool exact_receipt_required,
    bool has_local_finality,
    int32_t receipt_target_height,
    int32_t local_finality_height) noexcept;

/** Select the earliest exact-branch marker that forces retained-body replay. */
[[nodiscard]] const pq::BTCCPresealMarker*
SelectBTCCPresealRecomputeMarker(const pq::BTCCPresealState& state,
                                const CBlockIndex& candidate) noexcept;

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_CHAINLOCKS_H
