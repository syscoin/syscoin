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
#include <utility>
#include <vector>

namespace llmq {
class CChainLocksHandler;
namespace test {
class CChainLocksHandlerTestAccess;
}
}

namespace llmq_tests {
class PaymentAuditStoreTestAccess;
}

namespace llmq::pq {

enum class PaymentAuditStoreResult : uint8_t {
    ACCEPTED = 0,
    DUPLICATE_WITNESS,
    LIVE_CANDIDATE_SLOT_FULL,
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

enum class PaymentAuditPruneStatus : uint8_t {
    COMPLETE = 0,
    IN_PROGRESS,
    INVALID,
    CORRUPT,
    DATABASE_ERROR,
};

/** Work performed by one bounded archive-maintenance pass. */
struct PaymentAuditPruneProgress {
    PaymentAuditPruneStatus status{PaymentAuditPruneStatus::INVALID};
    std::size_t scanned_records{0};
    std::size_t scanned_value_bytes{0};
    std::size_t erased_records{0};
};

/**
 * An archive candidate decoded and validated while the store lock was held.
 * The IDs passed IsRecordValid(), so callers can reuse them without hashing
 * the large witness again. This view carries bytes, not durable verification
 * authority; consensus replay must request StoredVerifiedPaymentAudit.
 */
struct PaymentAuditCandidateView {
    uint256 logical_id;
    uint256 witness_id;
    FinalPaymentAudit audit;
};

/**
 * A coherent candidate-selection view. The revision is process-local and
 * changes after every successful mutation that can affect candidate
 * availability or ordering.
 */
struct PaymentAuditCandidateSnapshot {
    uint64_t revision{0};
    uint32_t epoch{0};
    std::vector<PaymentAuditCandidateView> ordered_candidates;
};

/**
 * Process-local authority to durably archive one exact certificate whose
 * signatures were already verified. Network bytes cannot construct this
 * capability or select a different authorization mask after verification.
 */
class VerifiedPaymentAuditAdmission final {
public:
    VerifiedPaymentAuditAdmission(
        const VerifiedPaymentAuditAdmission&) = delete;
    VerifiedPaymentAuditAdmission& operator=(
        const VerifiedPaymentAuditAdmission&) = delete;
    VerifiedPaymentAuditAdmission(
        VerifiedPaymentAuditAdmission&&) noexcept = default;
    VerifiedPaymentAuditAdmission& operator=(
        VerifiedPaymentAuditAdmission&&) noexcept = default;

    [[nodiscard]] const FinalPaymentAudit& Audit() const noexcept
    {
        return m_audit;
    }
    [[nodiscard]] uint8_t AuthorizationMask() const noexcept
    {
        return m_authorization_mask;
    }

private:
    VerifiedPaymentAuditAdmission(FinalPaymentAudit audit,
                                  uint8_t authorization_mask)
        : m_audit{std::move(audit)},
          m_authorization_mask{authorization_mask}
    {
    }

    FinalPaymentAudit m_audit;
    uint8_t m_authorization_mask{0};

    friend class ::llmq::CChainLocksHandler;
    friend class ::llmq::test::CChainLocksHandlerTestAccess;
    friend class ::llmq_tests::PaymentAuditStoreTestAccess;
    friend class PaymentAuditStore;
};

/**
 * Exact fsynced verification capability and archive revision observed under
 * one store lock. Only PaymentAuditStore can construct it; Get() and candidate
 * snapshots deliberately return non-authorizing certificate bytes.
 */
class StoredVerifiedPaymentAudit final {
public:
    [[nodiscard]] const FinalPaymentAudit& Audit() const noexcept
    {
        return m_audit;
    }
    [[nodiscard]] uint8_t AuthorizationMask() const noexcept
    {
        return m_authorization_mask;
    }
    [[nodiscard]] const uint256& LogicalId() const noexcept
    {
        return m_logical_id;
    }
    [[nodiscard]] const uint256& WitnessId() const noexcept
    {
        return m_witness_id;
    }
    [[nodiscard]] uint64_t Revision() const noexcept
    {
        return m_revision;
    }

private:
    StoredVerifiedPaymentAudit(FinalPaymentAudit audit,
                               uint256 logical_id,
                               uint256 witness_id,
                               uint8_t authorization_mask,
                               uint64_t revision)
        : m_audit{std::move(audit)},
          m_logical_id{std::move(logical_id)},
          m_witness_id{std::move(witness_id)},
          m_authorization_mask{authorization_mask},
          m_revision{revision}
    {
    }

    FinalPaymentAudit m_audit;
    uint256 m_logical_id;
    uint256 m_witness_id;
    uint8_t m_authorization_mask{0};
    uint64_t m_revision{0};

    friend class PaymentAuditStore;
};

/**
 * Exact certificate archive. Historical audit witnesses remain available
 * independently of the bounded live-row staging database until an
 * authenticated checkpoint retires their prefix.
 */
class PaymentAuditStore final {
public:
    static constexpr uint32_t DB_FORMAT_VERSION{1};
    static constexpr std::size_t MAX_LIVE_CANDIDATES{
        ACTIVE_QUORUMS};
    static constexpr std::size_t MAX_PRUNE_SCAN_RECORDS_PER_PASS{32};
    static constexpr std::size_t MAX_PRUNE_VALUE_BYTES_PER_PASS{8 << 20};
    static constexpr std::size_t MAX_PRUNE_ERASE_RECORDS_PER_PASS{64};

    PaymentAuditStore(fs::path path,
                      uint256 genesis_hash,
                      std::size_t cache_bytes = 8 << 20,
                      bool wipe = false);

    [[nodiscard]] bool IsHealthy() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Avoid expensive verification when an unreferenced live certificate
     * cannot enter its deterministic missing-quorum slot. Required historical
     * witnesses deliberately bypass this admission hint and use
     * AcceptVerified() with required_witness set.
     */
    [[nodiscard]] PaymentAuditStoreResult ProbeLiveCandidateSlot(
        uint32_t epoch, uint8_t selected_quorum_mask) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] PaymentAuditStoreResult AcceptVerified(
        VerifiedPaymentAuditAdmission admission,
        bool required_witness = false)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<FinalPaymentAudit> Get(
        const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<StoredVerifiedPaymentAudit>
    GetVerifiedWithCandidateRevision(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * The preferred applied witness plus at most four bounded live candidates,
     * one for each possible missing reporter quorum.
     * Older applied witnesses remain directly addressable by witness ID but
     * are deliberately excluded from live carrier selection. A reorg can
     * change the seal or probation root, so a new branch-compatible candidate
     * must be selectable before any carrier can reference it.
     */
    [[nodiscard]] std::optional<PaymentAuditCandidateSnapshot>
    GetEpochCandidateSnapshot(uint32_t epoch) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** A healthy-store token suitable for invalidating derived local caches. */
    [[nodiscard]] std::optional<uint64_t> ObserveCandidateRevision() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool IsCandidateRevisionCurrent(uint64_t revision) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Cheap key-presence check for inventory admission. Full record decoding
     * and witness validation remain on Get()/certificate verification paths. */
    [[nodiscard]] bool Has(const uint256& witness_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Mark the exact applied carrier dependency as preferred. Applied
     * witnesses remain available for block-index fork replay until an
     * authenticated checkpoint retires their epoch; only never-referenced
     * candidates are pruned before then.
     */
    [[nodiscard]] PaymentAuditStoreResult PinReferencedWitness(
        uint32_t epoch, const uint256& witness_id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    /** Drain bounded passes until a strictly monotonic boundary completes. */
    [[nodiscard]] bool PruneThroughCheckpoint(
        const PaymentAuditStoreCheckpoint& checkpoint)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /**
     * Validate and retire one bounded portion of an authenticated prefix.
     * The first pass durably installs a logical floor and intent; subsequent
     * calls with the same checkpoint resume after crashes.
     */
    [[nodiscard]] PaymentAuditPruneProgress PruneThroughCheckpointStep(
        const PaymentAuditStoreCheckpoint& checkpoint)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PaymentAuditStoreCheckpoint>
    GetPruneCheckpoint() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] std::optional<PaymentAuditStoreCheckpoint>
    GetPendingPruneCheckpoint() const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    enum class PrunePhase : uint8_t {
        VALIDATE_WITNESSES = 0,
        VALIDATE_EPOCHS,
        VALIDATE_REFERENCES,
        VALIDATE_PRESENCE,
        ERASE_WITNESSES,
        ERASE_EPOCHS,
    };

    struct PruneIntentState {
        PaymentAuditStoreCheckpoint checkpoint;
        PrunePhase phase{PrunePhase::VALIDATE_WITNESSES};
        bool has_cursor{false};
        uint32_t epoch_cursor{0};
        uint256 witness_cursor;
    };

    [[nodiscard]] std::optional<FinalPaymentAudit> GetLocked(
        const uint256& witness_id,
        uint8_t* authorization_mask = nullptr,
        uint256* logical_id = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void Initialize() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    [[nodiscard]] bool CanAdvanceCandidateRevision() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void AdvanceCandidateRevision() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    [[nodiscard]] const PaymentAuditStoreCheckpoint*
    EffectivePruneCheckpointLocked() const
        EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    uint256 m_genesis_hash;
    mutable CDBWrapper m_db;
    mutable Mutex m_mutex;
    mutable std::optional<PaymentAuditStoreResult> m_failure
        GUARDED_BY(m_mutex);
    mutable uint64_t m_candidate_revision GUARDED_BY(m_mutex){1};
    std::optional<PaymentAuditStoreCheckpoint> m_prune_checkpoint
        GUARDED_BY(m_mutex);
    std::optional<PruneIntentState> m_prune_intent
        GUARDED_BY(m_mutex);
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_STORE_H
