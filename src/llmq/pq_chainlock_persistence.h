// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H

#include <dbwrapper.h>
#include <llmq/pq_chainlock_store.h>
#include <llmq/pq_payment_audit.h>

#include <cstdint>
#include <memory>
#include <optional>

namespace llmq::pq {

/** These one-byte keys are part of the fail-closed on-disk schema. */
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_SCHEMA_KEY{1};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BEST_KEY{2};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_UNSEALED_BTCC_KEY{3};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_CATCHUP_MARKER_KEY{4};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BTCC_PRESEAL_KEY{5};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_BTCC_PROSPECTIVE_PRESEAL_KEY{6};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PRESEAL_KEY{7};
inline constexpr uint8_t PQ_CHAINLOCK_PERSISTENCE_PAYMENT_AUDIT_PROSPECTIVE_PRESEAL_KEY{8};

/**
 * Crash-durable bounds for one deferred BTCC/NEVM replay obligation.
 *
 * The earliest carrier is the block-pruning floor. The terminal receipt is
 * the exact certificate dependency currently needed to extend the
 * authenticated prefix; its predecessor state lets replay recompute the
 * complete marker range without treating a later certificate as an arbitrary
 * finality rebase.
 */
struct BTCCPresealMarker {
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    BTCCReceiptState predecessor_receipt_state;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    BTCCReceipt terminal_receipt;
    uint64_t revision{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return earliest_carrier_height >= 0 &&
               !earliest_carrier_hash.IsNull() &&
               predecessor_receipt_state.IsStructurallyValid() &&
               terminal_carrier_height >= earliest_carrier_height &&
               !terminal_carrier_hash.IsNull() &&
               terminal_receipt.IsStructurallyValid() &&
               !terminal_receipt.IsNull() && revision > 0;
    }

    friend bool operator==(const BTCCPresealMarker&,
                           const BTCCPresealMarker&) = default;
};

/**
 * Crash-durable replay obligations for the active branch and the one
 * prospective most-work branch ActivateBestChain can be evaluating.
 *
 * Keeping both prevents a prospective carrier from erasing an earlier active
 * boundary before the prospective branch is durably activated.
 */
struct BTCCPresealState {
    std::optional<BTCCPresealMarker> active;
    std::optional<BTCCPresealMarker> prospective;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return (!active || active->IsStructurallyValid()) &&
               (!prospective || prospective->IsStructurallyValid()) &&
               (!active || !prospective ||
                active->terminal_carrier_height !=
                    prospective->terminal_carrier_height ||
                active->terminal_carrier_hash !=
                    prospective->terminal_carrier_hash);
    }

    [[nodiscard]] bool IsEmpty() const noexcept
    {
        return !active && !prospective;
    }

    friend bool operator==(const BTCCPresealState&,
                           const BTCCPresealState&) = default;
};

/**
 * Crash-durable boundary for compact historical payment-audit replay.
 *
 * The receipt carries the deterministic transition bitmap, so the exact large
 * audit witness is not needed to reconstruct state.  The reconstructed prefix
 * remains provisional until a normally verified descendant ChainLock signs
 * both the cumulative receipt state and the resulting probation-state root.
 */
struct PaymentAuditPresealMarker {
    int32_t earliest_carrier_height{-1};
    uint256 earliest_carrier_hash;
    PaymentAuditReceiptState predecessor_receipt_state;
    uint256 predecessor_probation_state_hash;
    int32_t terminal_carrier_height{-1};
    uint256 terminal_carrier_hash;
    PaymentAuditReceipt terminal_receipt;
    uint64_t revision{0};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return earliest_carrier_height >= 0 &&
               !earliest_carrier_hash.IsNull() &&
               predecessor_receipt_state.IsStructurallyValid() &&
               !predecessor_probation_state_hash.IsNull() &&
               terminal_carrier_height >= earliest_carrier_height &&
               !terminal_carrier_hash.IsNull() &&
               terminal_receipt.IsStructurallyValid() &&
               !terminal_receipt.IsNull() &&
               terminal_receipt.carrier_height == terminal_carrier_height &&
               revision > 0;
    }

    friend bool operator==(const PaymentAuditPresealMarker&,
                           const PaymentAuditPresealMarker&) = default;
};

struct PaymentAuditPresealState {
    std::optional<PaymentAuditPresealMarker> active;
    std::optional<PaymentAuditPresealMarker> prospective;

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return (!active || active->IsStructurallyValid()) &&
               (!prospective || prospective->IsStructurallyValid()) &&
               (!active || !prospective ||
                active->terminal_carrier_height !=
                    prospective->terminal_carrier_height ||
                active->terminal_carrier_hash !=
                    prospective->terminal_carrier_hash);
    }

    [[nodiscard]] bool IsEmpty() const noexcept
    {
        return !active && !prospective;
    }

    friend bool operator==(const PaymentAuditPresealState&,
                           const PaymentAuditPresealState&) = default;
};

enum class ChainLockPersistenceError : uint8_t {
    NONE = 0,
    INVALID_CHAINLOCK,
    STALE_HEIGHT,
    HEIGHT_CONFLICT,
    NON_MONOTONIC_BTCC,
    NON_MONOTONIC_RECEIPT_STATE,
    IO_FAILURE,
};

/**
 * Coherent small snapshot of the validated durable certificate records.
 *
 * The revision is process-local: an empty database starts at zero, a restart
 * with either record starts at one, and each successful non-idempotent
 * certificate mutation advances it once. Marker-only writes do not affect it.
 */
struct DurableFinalityStateView {
    uint64_t certificate_revision{0};
    std::optional<FinalChainLockRecordMetadata> best;
    std::optional<FinalChainLockRecordMetadata> unsealed_btcc;

    friend bool operator==(const DurableFinalityStateView&,
                           const DurableFinalityStateView&) = default;
};

/**
 * Durable storage for the single best post-quantum ChainLock certificate.
 *
 * The database schema binds the record to the network genesis, complete
 * finality configuration, immutable anchors, and fixed cryptographic profile.
 * Construction validates every database key and every byte of the record;
 * callers must still perform full branch, roster, and signature verification
 * before importing LoadBest() into live finality state.
 */
class PQChainLockPersistence final {
public:
    PQChainLockPersistence(DBParams db_params,
                           uint256 genesis_hash,
                           ChainLockFinalityStoreConfig config);
    ~PQChainLockPersistence();

    PQChainLockPersistence(const PQChainLockPersistence&) = delete;
    PQChainLockPersistence& operator=(const PQChainLockPersistence&) = delete;

    [[nodiscard]] bool HasBest() const;
    [[nodiscard]] DurableFinalityStateView GetFinalityState() const;
    [[nodiscard]] std::optional<FinalChainLock> LoadBest() const;
    [[nodiscard]] std::optional<FinalChainLock> LoadUnsealedBTCC() const;
    [[nodiscard]] bool HasCatchupMarker() const;
    [[nodiscard]] BTCCPresealState LoadBTCCPresealState() const;
    [[nodiscard]] PaymentAuditPresealState
    LoadPaymentAuditPresealState() const;

    /**
     * Synchronously replace the durable winner. An identical write is
     * idempotent; stale, conflicting, or BTCC-regressing records are rejected.
     */
    [[nodiscard]] bool PersistBest(
        const FinalChainLock& chainlock,
        ChainLockPersistenceError* error = nullptr);

    /**
     * Retain a fully verified stale ADVANCE needed by an exact on-chain
     * receipt without changing the finality winner.
     */
    [[nodiscard]] bool PersistUnsealedBTCC(
        const FinalChainLock& chainlock,
        ChainLockPersistenceError* error = nullptr);

    /** Atomically advance the winner and highest catch-up audit marker. */
    [[nodiscard]] bool PersistCatchupBest(
        const FinalChainLock& chainlock,
        ChainLockPersistenceError* error = nullptr,
        const std::optional<BTCCCursorReconciliationProof>&
            btcc_cursor_reconciliation = std::nullopt);

    /** Atomically replace both deferred-NEVM branch obligations. */
    [[nodiscard]] bool PersistBTCCPresealState(
        const BTCCPresealState& state,
        ChainLockPersistenceError* error = nullptr);

    /** Synchronously clear both boundaries after authenticated replay. */
    [[nodiscard]] bool ClearBTCCPresealState(
        ChainLockPersistenceError* error = nullptr);

    /** Atomically replace both deferred payment-audit branch obligations. */
    [[nodiscard]] bool PersistPaymentAuditPresealState(
        const PaymentAuditPresealState& state,
        ChainLockPersistenceError* error = nullptr);

    /** Clear both payment-audit boundaries after a durable covering seal. */
    [[nodiscard]] bool ClearPaymentAuditPresealState(
        ChainLockPersistenceError* error = nullptr);

private:
    struct Impl;
    const std::unique_ptr<Impl> m_impl;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_PERSISTENCE_H
