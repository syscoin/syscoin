// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_PAYMENT_PROBATION_H
#define SYSCOIN_EVO_PQ_PAYMENT_PROBATION_H

#include <llmq/pq_payment_audit.h>

#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace llmq::pq {

inline constexpr uint16_t PQ_PAYMENT_PROBATION_STATE_VERSION{1};
inline constexpr uint16_t PQ_PAYMENT_PROBATION_DIFF_VERSION{1};
inline constexpr uint8_t PQ_PAYMENT_PROBATION_MAX_MISSES{2};
inline constexpr std::size_t PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS{
    QUORUM_MIN_VALID};
inline constexpr std::size_t MAX_PQ_PAYMENT_PROBATION_ENTRIES{65'535};
inline constexpr std::size_t MAX_PQ_PAYMENT_PROBATION_CHANGES{
    2 * MAX_PQ_PAYMENT_PROBATION_ENTRIES};
static_assert(MAX_PQ_PAYMENT_PROBATION_CHANGES <=
              std::numeric_limits<uint32_t>::max());
inline constexpr std::string_view PQ_PAYMENT_PROBATION_STATE_HASH_DOMAIN{
    "SYS_PQ_PAYMENT_PROBATION_STATE_V1"};

struct PQPaymentAuditReceiptIdentity {
    uint32_t epoch{0};
    int32_t carrier_height{-1};
    /** Signature-independent hash of the exact classified audit result. */
    uint256 receipt_id;

    SERIALIZE_METHODS(PQPaymentAuditReceiptIdentity, obj)
    {
        READWRITE(obj.epoch, obj.carrier_height, obj.receipt_id);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQPaymentAuditReceiptIdentity&,
                           const PQPaymentAuditReceiptIdentity&) = default;
};

struct PQPaymentProbationCursor {
    uint8_t has_receipt{0};
    PQPaymentAuditReceiptIdentity receipt;

    SERIALIZE_METHODS(PQPaymentProbationCursor, obj)
    {
        READWRITE(obj.has_receipt, obj.receipt);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQPaymentProbationCursor&,
                           const PQPaymentProbationCursor&) = default;
};

struct PQPaymentProbationEntry {
    uint256 pro_tx_hash;
    uint8_t consecutive_misses{0};
    int32_t payment_eligible_since_height{-1};

    SERIALIZE_METHODS(PQPaymentProbationEntry, obj)
    {
        READWRITE(obj.pro_tx_hash, obj.consecutive_misses,
                  obj.payment_eligible_since_height);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] bool IsPaymentWithheld() const noexcept
    {
        return consecutive_misses == PQ_PAYMENT_PROBATION_MAX_MISSES;
    }
    friend bool operator==(const PQPaymentProbationEntry&,
                           const PQPaymentProbationEntry&) = default;
};

/** Sparse, sorted payment-only state. It is intentionally independent of PoSe. */
struct PQPaymentProbationState {
    uint16_t version{PQ_PAYMENT_PROBATION_STATE_VERSION};
    PQPaymentProbationCursor cursor;
    std::vector<PQPaymentProbationEntry> entries;

    SERIALIZE_METHODS(PQPaymentProbationState, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ payment probation state");
        });
        READWRITE(obj.version, obj.cursor);
        uint16_t entry_count{static_cast<uint16_t>(obj.entries.size())};
        SER_WRITE(obj, if (obj.entries.size() >
                           MAX_PQ_PAYMENT_PROBATION_ENTRIES) {
            throw std::ios_base::failure(
                "too many PQ payment probation entries");
        });
        READWRITE(entry_count);
        SER_READ(obj, obj.entries.resize(entry_count));
        for (auto& entry : obj.entries) READWRITE(entry);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ payment probation state");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] uint8_t MissCount(const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] bool IsPaymentWithheld(
        const uint256& pro_tx_hash) const noexcept;
    [[nodiscard]] int32_t PaymentEligibleSinceHeight(
        const uint256& pro_tx_hash) const noexcept;
    friend bool operator==(const PQPaymentProbationState&,
                           const PQPaymentProbationState&) = default;
};

struct PQPaymentProbationChange {
    uint256 pro_tx_hash;
    uint8_t before_misses{0};
    uint8_t after_misses{0};
    int32_t before_payment_eligible_since_height{-1};
    int32_t after_payment_eligible_since_height{-1};

    SERIALIZE_METHODS(PQPaymentProbationChange, obj)
    {
        READWRITE(obj.pro_tx_hash, obj.before_misses, obj.after_misses,
                  obj.before_payment_eligible_since_height,
                  obj.after_payment_eligible_since_height);
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQPaymentProbationChange&,
                           const PQPaymentProbationChange&) = default;
};

/** Exact inverse journal for one accepted receipt transition. */
struct PQPaymentProbationDiff {
    uint16_t version{PQ_PAYMENT_PROBATION_DIFF_VERSION};
    PQPaymentProbationCursor previous_cursor;
    PQPaymentAuditReceiptIdentity applied_receipt;
    uint256 previous_state_hash;
    uint256 applied_state_hash;
    std::vector<PQPaymentProbationChange> changes;

    SERIALIZE_METHODS(PQPaymentProbationDiff, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ payment probation diff");
        });
        READWRITE(obj.version, obj.previous_cursor, obj.applied_receipt,
                  obj.previous_state_hash, obj.applied_state_hash);
        uint32_t change_count{static_cast<uint32_t>(obj.changes.size())};
        SER_WRITE(obj, if (obj.changes.size() >
                           MAX_PQ_PAYMENT_PROBATION_CHANGES) {
            throw std::ios_base::failure(
                "too many PQ payment probation changes");
        });
        READWRITE(change_count);
        SER_READ(obj, if (change_count >
                          MAX_PQ_PAYMENT_PROBATION_CHANGES) {
            throw std::ios_base::failure(
                "too many PQ payment probation changes");
        });
        SER_READ(obj, obj.changes.resize(change_count));
        for (auto& change : obj.changes) READWRITE(change);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("invalid PQ payment probation diff");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PQPaymentProbationDiff&,
                           const PQPaymentProbationDiff&) = default;
};

/** Hash the complete canonical state so undo cannot silently preserve drift. */
[[nodiscard]] std::optional<uint256> GetPQPaymentProbationStateHash(
    const PQPaymentProbationState& state);

/**
 * All membership collections are exact transition inputs. The two collateral
 * lists must be strictly sorted; current_valid_pro_tx_hashes must be a subset
 * of existing_pro_tx_hashes. Service, operator-key, revive, and PoSe fields do
 * not enter this state machine.
 */
struct PQPaymentProbationTransitionInput {
    PQPaymentAuditReceiptIdentity receipt;
    std::array<uint256, QUORUM_SIZE> frozen_roster;
    QuorumBitmap roster_valid_members{};
    QuorumBitmap observed_members{};
    std::vector<uint256> existing_pro_tx_hashes;
    std::vector<uint256> current_valid_pro_tx_hashes;

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
};

enum class PQPaymentProbationError : uint8_t {
    NONE = 0,
    INVALID_STATE,
    INVALID_RECEIPT,
    DUPLICATE_RECEIPT,
    CONFLICTING_RECEIPT,
    OUT_OF_ORDER_RECEIPT,
    INVALID_ROSTER,
    INVALID_BITMAP,
    INVALID_COLLATERAL_SET,
    INVALID_CURRENT_VALID_SET,
    INVALID_RESULT,
    INVALID_DIFF,
    UNDO_MISMATCH,
    INVALID_PAYMENT_QUEUE,
};

struct PQPaymentProbationTransitionResult {
    PQPaymentProbationState state;
    PQPaymentProbationDiff undo;
    uint16_t effective_observed_count{0};
    bool conclusive{false};
    /** Previously withheld members that supplied a positive observation. */
    std::vector<uint256> recovered_pro_tx_hashes;
    /** State entries removed because their collateral no longer exists. */
    std::vector<uint256> pruned_pro_tx_hashes;
};

[[nodiscard]] std::optional<PQPaymentProbationTransitionResult>
ApplyPQPaymentProbationTransition(
    const PQPaymentProbationState& previous,
    const PQPaymentProbationTransitionInput& input,
    PQPaymentProbationError* error = nullptr);

[[nodiscard]] std::optional<PQPaymentProbationState>
UndoPQPaymentProbationTransition(
    const PQPaymentProbationState& current,
    const PQPaymentProbationDiff& undo,
    PQPaymentProbationError* error = nullptr);

struct PQPaymentPayeeSelection {
    std::optional<uint256> pro_tx_hash;
    bool used_all_probated_fallback{false};
};

/** Select the first non-withheld ordinary payee, falling back to the ordinary
 * queue head when every candidate is withheld. */
[[nodiscard]] std::optional<PQPaymentPayeeSelection>
SelectPQPaymentPayee(
    const PQPaymentProbationState& state,
    std::span<const uint256> ordinary_payment_queue,
    PQPaymentProbationError* error = nullptr);

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_PAYMENT_PROBATION_H
