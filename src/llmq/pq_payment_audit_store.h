// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STORE_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STORE_H

#include <dbwrapper.h>
#include <llmq/pq_payment_audit.h>
#include <sync.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace llmq::pq {

enum class PaymentAuditStoreResult : uint8_t {
    ACCEPTED = 0,
    DUPLICATE_WITNESS,
    VARIANT_LIMIT,
    INVALID,
    CORRUPT,
    DATABASE_ERROR,
};

/**
 * Monotonic archive boundary supplied only after a covering ChainLock has
 * authenticated the corresponding cumulative payment-audit receipt state and
 * that exact certificate has become the durable finality winner.
 */
struct PaymentAuditStoreCheckpoint {
    uint32_t prune_through_epoch{0};
    int32_t covered_through_height{-1};
    uint256 covered_through_hash;
    PaymentAuditReceiptState authenticated_receipt_state;
    uint256 authenticated_probation_state_hash;
    int32_t authorizing_target_height{-1};
    uint256 authorizing_target_hash;
    uint256 authorizing_chainlock_logical_id;
    uint256 authorizing_chainlock_witness_id;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        const auto& cursor{authenticated_receipt_state.cursor};
        return covered_through_height >= 0 &&
               !covered_through_hash.IsNull() &&
               authenticated_receipt_state.IsStructurallyValid() &&
               !authenticated_probation_state_hash.IsNull() &&
               (cursor.IsNull() ||
                (cursor.epoch <= prune_through_epoch &&
                 cursor.carrier_height <= covered_through_height)) &&
               authorizing_target_height >= covered_through_height &&
               !authorizing_target_hash.IsNull() &&
               !authorizing_chainlock_logical_id.IsNull() &&
               !authorizing_chainlock_witness_id.IsNull();
    }

    friend bool operator==(const PaymentAuditStoreCheckpoint&,
                           const PaymentAuditStoreCheckpoint&) = default;
};

/**
 * Exact V2 certificate archive. Historical audit witnesses remain available
 * independently of the bounded live-row staging database until an
 * authenticated checkpoint retires their prefix.
 */
class PaymentAuditStore final {
public:
    static constexpr uint32_t DB_FORMAT_VERSION{5};
    static constexpr std::size_t MAX_UNREFERENCED_VARIANTS{
        ACTIVE_QUORUMS};

    PaymentAuditStore(fs::path path,
                      uint256 genesis_hash,
                      std::size_t cache_bytes = 8 << 20,
                      bool wipe = false);

    [[nodiscard]] bool IsHealthy() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] PaymentAuditStoreResult AcceptVerified(
        const FinalPaymentAudit& audit,
        bool required_witness = false)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<FinalPaymentAudit> Get(
        const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<FinalPaymentAudit> GetByEpoch(
        uint32_t epoch) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * The preferred applied witness plus at most four bounded live variants.
     * Older applied witnesses remain directly addressable by witness ID but
     * are deliberately excluded from live carrier selection.
     */
    [[nodiscard]] std::vector<FinalPaymentAudit> GetEpochCandidates(
        uint32_t epoch) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Cheap key-presence check for inventory admission. Full record decoding
     * and witness validation remain on Get()/certificate verification paths. */
    [[nodiscard]] bool Has(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Mark the exact applied carrier dependency as preferred. Applied
     * witnesses remain available for block-index fork replay until an
     * authenticated checkpoint retires their epoch; only never-referenced
     * variants are pruned before then.
     */
    [[nodiscard]] PaymentAuditStoreResult PinReferencedWitness(
        uint32_t epoch, const uint256& witness_id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /**
     * Atomically persist a strictly monotonic authenticated boundary and erase
     * every archive record at or below its epoch. Reapplying the exact boundary
     * is idempotent; regressions and equal-epoch conflicts are rejected.
     */
    [[nodiscard]] bool PruneThroughCheckpoint(
        const PaymentAuditStoreCheckpoint& checkpoint)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PaymentAuditStoreCheckpoint>
    GetPruneCheckpoint() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    void Initialize() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    uint256 m_genesis_hash;
    mutable CDBWrapper m_db;
    mutable Mutex m_mutex;
    mutable std::optional<PaymentAuditStoreResult> m_failure
        GUARDED_BY(m_mutex);
    std::optional<PaymentAuditStoreCheckpoint> m_prune_checkpoint
        GUARDED_BY(m_mutex);
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STORE_H
