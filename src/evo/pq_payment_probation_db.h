// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_PAYMENT_PROBATION_DB_H
#define SYSCOIN_EVO_PQ_PAYMENT_PROBATION_DB_H

#include <evo/evodb.h>
#include <evo/pq_payment_probation.h>
#include <llmq/pq_payment_audit_store.h>
#include <saltedhasher.h>
#include <sync.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <optional>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

class CDeterministicMNManager;

namespace llmq::pq {

struct PQPaymentProbationStateViewData;
struct PQPaymentProbationStateViewOwner;
class PQPaymentProbationManager;

namespace test {
class PQPaymentProbationManagerTestAccess;
}

/**
 * Immutable ownership handle for one hash-authenticated probation state.
 * The backing state and its lookup index are shared by all readers of the
 * same root without exposing mutable cache or database ownership.
 */
class PQPaymentProbationStateView {
public:
    PQPaymentProbationStateView() = default;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] uint256 StateHash() const noexcept;
    [[nodiscard]] const PQPaymentProbationState* State() const noexcept;
    [[nodiscard]] uint8_t MissCount(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] bool IsPaymentWithheld(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] int32_t PaymentEligibleSinceHeight(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] bool SharesStateWith(
        const PQPaymentProbationStateView& other) const noexcept;

private:
    explicit PQPaymentProbationStateView(
        std::shared_ptr<const PQPaymentProbationStateViewData> state);

    std::shared_ptr<const PQPaymentProbationStateViewData> m_state;

    friend class PQPaymentProbationManager;
    friend class PQPaymentProbationTransitionView;
};

/** Immutable transition whose previous and result roots are manager-authenticated. */
class PQPaymentProbationTransitionView {
public:
    PQPaymentProbationTransitionView() = default;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] const PQPaymentProbationStateView& Result() const noexcept;
    [[nodiscard]] uint256 PreviousStateHash() const noexcept;
    [[nodiscard]] const PQPaymentAuditReceiptIdentity& AppliedReceipt() const noexcept;
    [[nodiscard]] uint64_t ProvenanceGeneration() const noexcept;

private:
    PQPaymentProbationStateView m_result;
    uint256 m_previous_state_hash;
    PQPaymentAuditReceiptIdentity m_applied_receipt;

    friend class PQPaymentProbationManager;
};

enum class PQPaymentProbationTransitionStatus : uint8_t {
    READY = 0,
    INVALID,
    LOCAL_ERROR,
};

struct PQPaymentProbationTransitionOutcome {
    PQPaymentProbationTransitionStatus status{
        PQPaymentProbationTransitionStatus::LOCAL_ERROR};
    PQPaymentProbationError error{PQPaymentProbationError::INVALID_STATE};
    std::optional<PQPaymentProbationTransitionView> transition;
};

struct PQPaymentProbationGCRequest {
    PaymentAuditStoreCheckpoint checkpoint;
    std::vector<uint256> retained_state_hashes;

    friend bool operator==(const PQPaymentProbationGCRequest&,
                           const PQPaymentProbationGCRequest&) = default;
};

enum class PQPaymentProbationPruneStatus : uint8_t {
    COMPLETE = 0,
    IN_PROGRESS,
    INVALID,
    CORRUPT,
    DATABASE_ERROR,
};

/** Work performed by one bounded probation-state maintenance pass. */
struct PQPaymentProbationPruneProgress {
    PQPaymentProbationPruneStatus status{
        PQPaymentProbationPruneStatus::INVALID};
    std::size_t scanned_records{0};
    std::size_t scanned_value_bytes{0};
    std::size_t erased_records{0};
};

/**
 * Hash-addressed branch state for payment probation. Only receipt transitions
 * create records; intervening blocks retain the parent root in CBlockIndex.
 */
class PQPaymentProbationManager {
private:
    enum class GCPhase : uint8_t {
        VALIDATE_RETAINED = 0,
        VALIDATE_RECORDS,
        ERASE_RECORDS,
    };

    struct GCIntentState {
        PQPaymentProbationGCRequest request;
        GCPhase phase{GCPhase::VALIDATE_RETAINED};
        uint8_t retained_index{0};
        bool has_cursor{false};
        uint256 cursor;
    };

    struct CompactTransitionResult {
        PQPaymentProbationState state;
        uint256 previous_state_hash;
        PQPaymentAuditReceiptIdentity applied_receipt;
        uint256 applied_state_hash;
    };

    using MembershipResolver = std::function<
        PQPaymentProbationMembership(const uint256&)>;

    /** Compact core used only after this manager authenticates the view. */
    [[nodiscard]] static std::optional<CompactTransitionResult>
    ApplyCompactTransition(
        const PQPaymentProbationStateView& previous,
        const PQPaymentProbationTransitionContext& context,
        const MembershipResolver& membership,
        PQPaymentProbationError* error);

    static constexpr std::size_t STATE_VIEW_CACHE_SIZE{8};
    using StateViewDataPtr =
        std::shared_ptr<const PQPaymentProbationStateViewData>;
    using StateViewCacheList =
        std::list<std::pair<uint256, StateViewDataPtr>>;
    using StateViewCacheMap = std::unordered_map<
        uint256, StateViewCacheList::iterator, StaticSaltedHasher>;

    mutable Mutex m_mutex;
    std::unique_ptr<CEvoDB<uint256, PQPaymentProbationState,
                           StaticSaltedHasher>> m_state_db;
    uint256 m_empty_state_hash;
    std::shared_ptr<const PQPaymentProbationStateViewOwner> m_view_owner;
    StateViewDataPtr m_empty_state_view;
    mutable StateViewCacheList m_state_view_cache GUARDED_BY(m_mutex);
    mutable StateViewCacheMap m_state_view_cache_index GUARDED_BY(m_mutex);
    mutable uint64_t m_state_view_cache_hits GUARDED_BY(m_mutex){0};
    mutable uint64_t m_state_view_cache_misses GUARDED_BY(m_mutex){0};
    mutable uint64_t m_state_view_builds GUARDED_BY(m_mutex){0};
    uint64_t m_state_view_generation GUARDED_BY(m_mutex){1};
    std::optional<PQPaymentProbationGCRequest> m_completed_gc
        GUARDED_BY(m_mutex);
    std::optional<GCIntentState> m_gc_intent GUARDED_BY(m_mutex);
    bool m_fail_next_gc_batch_for_testing GUARDED_BY(m_mutex){false};

    [[nodiscard]] const PQPaymentProbationGCRequest*
    EffectiveGCRequest() const EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool IsStateAllowedByGC(
        const uint256& state_hash,
        const PQPaymentProbationState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void InitializeGCState() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool WriteGCBatch(CDBBatch& batch)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    /** Build the index only after the caller authenticated the exact root. */
    [[nodiscard]] StateViewDataPtr BuildValidatedStateView(
        const uint256& state_hash,
        PQPaymentProbationState state) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool PublishStateView(
        StateViewDataPtr state,
        StateViewDataPtr* published = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool AuthenticateTransitionParent(
        const PQPaymentProbationStateView& previous,
        StateViewDataPtr& authenticated,
        uint64_t& generation,
        PQPaymentProbationError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PQPaymentProbationTransitionView>
    FinalizeTransition(
        StateViewDataPtr previous,
        uint64_t generation,
        CompactTransitionResult result,
        PQPaymentProbationError* error) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PQPaymentProbationTransitionView>
    ApplyTransitionWithMembership(
        const PQPaymentProbationStateView& previous,
        const PQPaymentProbationTransitionContext& context,
        const MembershipResolver& membership,
        PQPaymentProbationError* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
public:
    static constexpr std::size_t MAX_GC_RETAINED_ROOTS{16};
    static constexpr std::size_t MAX_GC_SCAN_RECORDS_PER_PASS{32};
    static constexpr std::size_t MAX_GC_VALUE_BYTES_PER_PASS{8 << 20};
    static constexpr std::size_t MAX_GC_ERASE_RECORDS_PER_PASS{32};

    explicit PQPaymentProbationManager(const DBParams& db_params);

    [[nodiscard]] const uint256& EmptyStateHash() const noexcept
    {
        return m_empty_state_hash;
    }

    /** Resolve one authenticated shared state without copying its entries. */
    [[nodiscard]] bool GetStateView(
        const uint256& state_hash,
        PQPaymentProbationStateView& view) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Compatibility copying API retained for tests. */
    [[nodiscard]] bool GetState(const uint256& state_hash,
                                PQPaymentProbationState& state) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Validate and optionally publish one immutable state record. */
    [[nodiscard]] bool CommitState(const PQPaymentProbationState& state,
                                   const uint256& expected_hash,
                                   bool fJustCheck)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Persist and publish the exact immutable result backing, or only verify it. */
    [[nodiscard]] bool CommitTransition(
        const PQPaymentProbationTransitionView& transition,
        bool fJustCheck,
        PQPaymentProbationStateView* published = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Monotonic provenance for prepared views; GC invalidates old results. */
    [[nodiscard]] uint64_t StateViewGeneration() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Order all earlier asynchronous state writes before a durable marker. */
    [[nodiscard]] bool Flush(bool fSync = true)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Return whether the last durable GC commit names the same authenticated
     * deletion boundary. Authorizer refreshes do not change what can be
     * deleted. The marker lives with the state DB, so rebuilding chainstate
     * clears it and forces one repair pass.
     */
    [[nodiscard]] bool IsGCCompleteForCheckpoint(
        const PaymentAuditStoreCheckpoint& checkpoint) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Synchronously discard checkpoint-covered states while preserving every
     * explicitly retained branch root. The authenticated audit checkpoint
     * must already be durable before this irreversible operation begins.
     */
    [[nodiscard]] bool PruneStatesThroughCheckpoint(
        const PaymentAuditStoreCheckpoint& checkpoint,
        std::span<const uint256> retained_state_hashes)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Validate and retire one bounded slice. The first pass durably installs
     * the logical floor; later calls resume the exact phase and physical key.
     */
    [[nodiscard]] PQPaymentProbationPruneProgress
    PruneStatesThroughCheckpointStep(
        const PaymentAuditStoreCheckpoint& checkpoint,
        std::span<const uint256> retained_state_hashes)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    [[nodiscard]] std::optional<PQPaymentProbationGCRequest>
    GetPendingGCRequest() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    CEvoDB<uint256, PQPaymentProbationState, StaticSaltedHasher>&
    StateDatabaseForTesting() noexcept
    {
        return *m_state_db;
    }

    friend class test::PQPaymentProbationManagerTestAccess;
    friend class ::CDeterministicMNManager;
};

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_PAYMENT_PROBATION_DB_H
