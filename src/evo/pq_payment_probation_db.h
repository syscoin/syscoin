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

#include <memory>
#include <span>

namespace llmq::pq {

/**
 * Hash-addressed branch state for payment probation. Only receipt transitions
 * create records; intervening blocks retain the parent root in CBlockIndex.
 */
class PQPaymentProbationManager {
private:
    mutable Mutex m_mutex;
    std::unique_ptr<CEvoDB<uint256, PQPaymentProbationState,
                           StaticSaltedHasher>> m_state_db;
    uint256 m_empty_state_hash;

public:
    explicit PQPaymentProbationManager(const DBParams& db_params);

    [[nodiscard]] const uint256& EmptyStateHash() const noexcept
    {
        return m_empty_state_hash;
    }

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
};

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_PAYMENT_PROBATION_DB_H
