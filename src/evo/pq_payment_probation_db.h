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
#include <list>
#include <memory>
#include <span>
#include <unordered_map>
#include <utility>

namespace llmq::pq {

struct PQPaymentProbationStateViewData;
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
};

/**
 * Hash-addressed branch state for payment probation. Only receipt transitions
 * create records; intervening blocks retain the parent root in CBlockIndex.
 */
class PQPaymentProbationManager {
private:
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
    StateViewDataPtr m_empty_state_view;
    mutable StateViewCacheList m_state_view_cache GUARDED_BY(m_mutex);
    mutable StateViewCacheMap m_state_view_cache_index GUARDED_BY(m_mutex);
    mutable uint64_t m_state_view_cache_hits GUARDED_BY(m_mutex){0};
    mutable uint64_t m_state_view_cache_misses GUARDED_BY(m_mutex){0};
    mutable uint64_t m_state_view_builds GUARDED_BY(m_mutex){0};

    /** Build the index only after the caller authenticated the exact root. */
    [[nodiscard]] StateViewDataPtr BuildValidatedStateView(
        const uint256& state_hash,
        PQPaymentProbationState state) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] bool PublishStateView(
        StateViewDataPtr state,
        StateViewDataPtr* published = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void EvictStateView(const uint256& state_hash)
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
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

    CEvoDB<uint256, PQPaymentProbationState, StaticSaltedHasher>&
    StateDatabaseForTesting() noexcept
    {
        return *m_state_db;
    }

    friend class test::PQPaymentProbationManagerTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_PAYMENT_PROBATION_DB_H
