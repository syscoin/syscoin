// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_BTCC_H
#define SYSCOIN_LLMQ_PQ_BTCC_H

#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_types.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

class CBlock;
class CBlockIndex;
namespace Consensus {
struct Params;
}

// SYSCOIN: BTCPREV and BTCC are Syscoin coinbase commitments, not Bitcoin
// consensus fields. Keeping their tags beside the only bounded decoder avoids
// making the generic validation module an owner of this protocol surface.
inline constexpr uint8_t BTCPREV_MAGIC_BYTES[4]{'b', 't', 'c', 'p'};
inline constexpr uint8_t BTCC_RECEIPT_MAGIC_BYTES[4]{'b', 't', 'c', 'r'};

namespace llmq::pq {

inline constexpr uint32_t PQ_BTCC_CANDIDATE_PERIOD{10};
inline constexpr uint32_t PQ_BTCC_RECEIPT_PROPAGATION_BUFFER{5};
inline constexpr uint32_t PQ_BTCC_NEVM_LAG{
    PQ_CL_SIGN_LAG + PQ_BTCC_RECEIPT_PROPAGATION_BUFFER};
inline constexpr uint16_t PQ_BTCC_RECEIPT_VERSION{1};
inline constexpr std::string_view PQ_BTCC_RECEIPT_STATE_DOMAIN{
    "SYS_PQ_BTCC_RECEIPT_STATE_V1"};

static_assert(PQ_BTCC_NEVM_LAG == 10);

struct BTCCScheduleConfig {
    int32_t candidate_origin{-1};
    uint32_t candidate_period{PQ_BTCC_CANDIDATE_PERIOD};
    uint32_t nevm_injection_lag{PQ_BTCC_NEVM_LAG};

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const BTCCScheduleConfig&, const BTCCScheduleConfig&) = default;
};

/** Convert the pinned consensus fields into the runtime schedule object. */
[[nodiscard]] BTCCScheduleConfig GetBTCCScheduleConfig(
    const Consensus::Params& consensus) noexcept;

/**
 * Compact on-chain proof reference for one already-accepted ADVANCE
 * ChainLock. The fixed-size multi-megabyte certificate remains in the bounded finality
 * archive/relay layer; blocks carry only this exact fixed-width reference.
 *
 * A versioned all-zero/default body is the canonical null receipt. Carrier
 * slots are therefore always structurally present without making certificate
 * availability a mining-liveness dependency.
 */
struct BTCCReceipt {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(int32_t) + 2 * 32 +
        sizeof(int32_t) + 2 * 32};

    uint16_t version{PQ_BTCC_RECEIPT_VERSION};
    int32_t chainlock_target_height{-1};
    uint256 chainlock_target_hash;
    uint256 chainlock_logical_id;
    BTCCursor accepted_cursor;

    SERIALIZE_METHODS(BTCCReceipt, obj)
    {
        READWRITE(obj.version, obj.chainlock_target_height,
                  obj.chainlock_target_hash, obj.chainlock_logical_id,
                  obj.accepted_cursor);
    }

    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const;
    friend bool operator==(const BTCCReceipt&, const BTCCReceipt&) = default;
};

static_assert(BTCCReceipt::WIRE_SIZE == 138);

/** Deterministic signer choice embedded in one ChainLock statement. */
struct BTCCSelection {
    BTCCursor cursor;
    BTCCAdvance advance{BTCCAdvance::KEEP};

    friend bool operator==(const BTCCSelection&, const BTCCSelection&) = default;
};

enum class BTCCValidationError : uint8_t {
    NONE = 0,
    INVALID_CONFIG,
    INVALID_TARGET,
    INVALID_PREVIOUS_CURSOR,
    INVALID_CURSOR,
    INVALID_ADVANCE_FLAG,
    KEEP_MISMATCH,
    NON_MONOTONIC_ADVANCE,
    UNSCHEDULED_CANDIDATE,
    MISSING_ANCESTOR,
    SYS_HASH_MISMATCH,
    MISSING_BTCPREV,
    BTC_HASH_MISMATCH,
};

[[nodiscard]] bool IsBTCCCandidateHeight(
    const BTCCScheduleConfig& config, int32_t height) noexcept;

/** Return whether consensus requires a coinbase BTCPREV commitment here. */
[[nodiscard]] bool IsBTCPREVCommitmentHeight(
    const Consensus::Params& consensus, int32_t height) noexcept;

/**
 * Validate the consensus-visible cursor transition against one explicit
 * Syscoin branch. Bitcoin canonicality is deliberately outside Syscoin
 * consensus; full nodes validate the threshold certificate after this check.
 */
[[nodiscard]] bool ValidateBTCCursorTransition(
    const BTCCScheduleConfig& config,
    const CBlockIndex& target,
    const BTCCursor& previous,
    const BTCCursor& accepted,
    BTCCAdvance advance,
    BTCCValidationError* error = nullptr);

/**
 * Advance only when the ChainLock target itself is a scheduled BTC candidate.
 * If that exact block has no BTCPREV commitment (or the target is between BTC
 * slots), retain the previous cursor. This makes every ADVANCE uniquely
 * receiptable at target+10 and prevents stale-certificate rollover.
 */
[[nodiscard]] std::optional<BTCCSelection> SelectBTCCForChainLock(
    const BTCCScheduleConfig& config,
    const CBlockIndex& target,
    const BTCCursor& previous,
    BTCCValidationError* error = nullptr);

/** Return the scheduled source height injected while connecting current_height. */
[[nodiscard]] std::optional<int32_t> BTCCSourceHeightForNEVMInjection(
    const BTCCScheduleConfig& config, int32_t current_height) noexcept;

/** Fixed candidate-aligned carrier cadence, ten blocks after its source. */
[[nodiscard]] bool IsBTCCReceiptCarrierHeight(
    const BTCCScheduleConfig& config, int32_t height) noexcept;

/** Validate the compact receipt's target/cursor against one Syscoin branch. */
[[nodiscard]] bool ValidateBTCCReceiptOnBranch(
    const BTCCScheduleConfig& config,
    const CBlockIndex& carrier,
    const BTCCReceipt& receipt);

/** Update the branch-local receipt state; null carrier slots are no-ops. */
[[nodiscard]] std::optional<BTCCReceiptState> ApplyBTCCReceiptState(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& chainlock_schedule,
    const BTCCScheduleConfig& btcc_schedule,
    int32_t carrier_height,
    const uint256& carrier_hash,
    const BTCCReceiptState& previous,
    const BTCCReceipt& receipt);

/**
 * Reconstruct the exact receipt carried by one already-indexed carrier.
 * The caller supplies the per-carrier logical id retained by CBlockIndex;
 * every other byte is fixed by the schedule, branch, and indexed transition.
 */
[[nodiscard]] std::optional<BTCCReceipt> ReconstructBTCCReceipt(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& chainlock_schedule,
    const BTCCScheduleConfig& btcc_schedule,
    const CBlockIndex& carrier,
    const BTCCReceiptState& previous,
    const BTCCReceiptState& current,
    const uint256& receipt_logical_id);

} // namespace llmq::pq

// SYSCOIN: bounded, ambiguity-rejecting extraction belongs to the BTCC
// protocol module so ChainLocks does not depend on the special-tx dispatcher.
[[nodiscard]] bool ExtractBTCPREVCommitment(
    const CBlock& block, uint256& btc_prev_hash);
[[nodiscard]] bool ExtractBTCCReceipt(
    const CBlock& block, llmq::pq::BTCCReceipt& receipt);
/** True when the reserved receipt marker occurs in the bounded coinbase tail. */
[[nodiscard]] bool HasBTCCReceiptCommitment(const CBlock& block);

#endif // SYSCOIN_LLMQ_PQ_BTCC_H
