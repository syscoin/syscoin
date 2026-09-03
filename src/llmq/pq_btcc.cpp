// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_btcc.h>

#include <chain.h>
#include <consensus/params.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <limits>
#include <utility>
#include <vector>

namespace {

template <typename T, typename ParseFn>
bool ExtractUniqueTaggedTailObject(const std::vector<unsigned char>& data,
                                   const uint8_t (&magic)[4],
                                   size_t max_payload_size,
                                   T& out,
                                   ParseFn&& parse_fn)
{
    if (data.size() < sizeof(magic)) return false;

    const size_t search_start_offset{
        data.size() > sizeof(magic) + max_payload_size
            ? data.size() - sizeof(magic) - max_payload_size
            : 0};
    const auto search_begin{data.begin() + search_start_offset};
    auto search_end{data.end()};
    bool found{false};
    T parsed{};
    while (search_begin != search_end) {
        const auto it{std::find_end(search_begin, search_end,
                                    std::begin(magic), std::end(magic))};
        if (it == search_end) break;
        const auto payload_begin{std::next(it, sizeof(magic))};
        const size_t payload_size{
            static_cast<size_t>(std::distance(payload_begin, data.end()))};
        if (payload_size > max_payload_size) return false;

        const Span<const unsigned char> payload{
            data.data() + std::distance(data.begin(), payload_begin),
            payload_size};
        T candidate{};
        if (parse_fn(payload, candidate)) {
            // SYSCOIN: accepting either of two decodable tails would let the
            // same coinbase bytes acquire different consensus interpretations.
            if (found) return false;
            parsed = std::move(candidate);
            found = true;
        }
        search_end = it;
    }
    if (!found) return false;
    out = std::move(parsed);
    return true;
}

} // namespace

bool ExtractBTCPREVCommitment(const CBlock& block, uint256& btc_prev_hash)
{
    if (block.vtx.empty() || !block.vtx[0]) return false;
    std::vector<unsigned char> data;
    int output_index{-1};
    if (!GetSyscoinData(*block.vtx[0], data, output_index)) return false;
    constexpr size_t BTCPREV_PAYLOAD_SIZE{32};
    return ExtractUniqueTaggedTailObject(
        data, BTCPREV_MAGIC_BYTES, BTCPREV_PAYLOAD_SIZE, btc_prev_hash,
        [](Span<const unsigned char> payload, uint256& candidate) {
            if (payload.size() != BTCPREV_PAYLOAD_SIZE) return false;
            try {
                SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, payload};
                reader >> candidate;
                return reader.empty();
            } catch (const std::exception&) {
                return false;
            }
        });
}

bool ExtractBTCCReceipt(const CBlock& block, llmq::pq::BTCCReceipt& receipt)
{
    if (block.vtx.empty() || !block.vtx[0]) return false;
    std::vector<unsigned char> data;
    int output_index{-1};
    if (!GetSyscoinData(*block.vtx[0], data, output_index)) return false;

    constexpr std::size_t TRAILING_BTCPREV_SIZE{
        sizeof(BTCPREV_MAGIC_BYTES) + 32};
    constexpr std::size_t MAX_RECEIPT_TAIL{
        llmq::pq::BTCCReceipt::WIRE_SIZE + TRAILING_BTCPREV_SIZE};
    return ExtractUniqueTaggedTailObject(
        data, BTCC_RECEIPT_MAGIC_BYTES, MAX_RECEIPT_TAIL, receipt,
        [=](Span<const unsigned char> payload,
            llmq::pq::BTCCReceipt& candidate) {
            if (payload.size() == MAX_RECEIPT_TAIL) {
                const Span<const unsigned char> trailing{
                    payload.subspan(llmq::pq::BTCCReceipt::WIRE_SIZE)};
                if (trailing.size() != TRAILING_BTCPREV_SIZE ||
                    !std::equal(std::begin(BTCPREV_MAGIC_BYTES),
                                std::end(BTCPREV_MAGIC_BYTES),
                                trailing.begin())) {
                    return false;
                }
                payload = payload.first(llmq::pq::BTCCReceipt::WIRE_SIZE);
            }
            if (payload.size() != llmq::pq::BTCCReceipt::WIRE_SIZE) {
                return false;
            }
            try {
                SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, payload};
                reader >> candidate;
                return reader.empty() && candidate.IsStructurallyValid();
            } catch (const std::exception&) {
                return false;
            }
        });
}

bool HasBTCCReceiptCommitment(const CBlock& block)
{
    if (block.vtx.empty() || !block.vtx[0]) return false;
    std::vector<unsigned char> data;
    int output_index{-1};
    if (!GetSyscoinData(*block.vtx[0], data, output_index)) return false;
    constexpr std::size_t TRAILING_BTCPREV_SIZE{
        sizeof(BTCPREV_MAGIC_BYTES) + 32};
    constexpr std::size_t MAX_RECEIPT_TAIL{
        sizeof(BTCC_RECEIPT_MAGIC_BYTES) +
        llmq::pq::BTCCReceipt::WIRE_SIZE + TRAILING_BTCPREV_SIZE};
    const auto begin{data.size() > MAX_RECEIPT_TAIL
                         ? data.end() - MAX_RECEIPT_TAIL
                         : data.begin()};
    return std::search(begin, data.end(),
                       std::begin(BTCC_RECEIPT_MAGIC_BYTES),
                       std::end(BTCC_RECEIPT_MAGIC_BYTES)) != data.end();
}

namespace llmq::pq {
namespace {

void SetError(BTCCValidationError* error, BTCCValidationError value)
{
    if (error != nullptr) *error = value;
}

bool ValidateCursorOnBranch(const CBlockIndex& target,
                            const BTCCursor& cursor,
                            BTCCValidationError invalid_cursor,
                            BTCCValidationError* error)
{
    if (!cursor.IsStructurallyValid() || cursor.IsNull() ||
        cursor.sys_height > target.nHeight) {
        SetError(error, invalid_cursor);
        return false;
    }
    const CBlockIndex* source{target.GetAncestor(cursor.sys_height)};
    if (source == nullptr) {
        SetError(error, BTCCValidationError::MISSING_ANCESTOR);
        return false;
    }
    if (source->GetBlockHash() != cursor.sys_hash) {
        SetError(error, BTCCValidationError::SYS_HASH_MISMATCH);
        return false;
    }
    if (source->btcpPrevCommitment.IsNull()) {
        SetError(error, BTCCValidationError::MISSING_BTCPREV);
        return false;
    }
    if (source->btcpPrevCommitment != cursor.btc_hash) {
        SetError(error, BTCCValidationError::BTC_HASH_MISMATCH);
        return false;
    }
    return true;
}

} // namespace

BTCCScheduleConfig GetBTCCScheduleConfig(
    const Consensus::Params& consensus) noexcept
{
    return {
        consensus.nPQBTCCCandidateOrigin,
        PQ_BTCC_CANDIDATE_PERIOD,
        static_cast<uint32_t>(consensus.nPQBTCCNEVMInjectionLag),
    };
}

bool BTCCScheduleConfig::IsValid() const noexcept
{
    if (candidate_origin < 0 || candidate_period != PQ_BTCC_CANDIDATE_PERIOD ||
        nevm_injection_lag != PQ_BTCC_NEVM_LAG) {
        return false;
    }
    return static_cast<int64_t>(candidate_origin) + nevm_injection_lag <=
           std::numeric_limits<int32_t>::max();
}

bool BTCCReceipt::IsNull() const noexcept
{
    return version == PQ_BTCC_RECEIPT_VERSION &&
           chainlock_target_height == -1 && chainlock_target_hash.IsNull() &&
           chainlock_logical_id.IsNull() && accepted_cursor.IsNull();
}

bool BTCCReceipt::IsStructurallyValid() const
{
    if (version != PQ_BTCC_RECEIPT_VERSION) return false;
    if (IsNull()) return true;
    return chainlock_target_height >= 0 &&
           !chainlock_target_hash.IsNull() &&
           !chainlock_logical_id.IsNull() &&
           accepted_cursor.IsStructurallyValid() &&
           !accepted_cursor.IsNull() &&
           accepted_cursor.sys_height <= chainlock_target_height;
}

bool BTCCReceiptAdvancesCursor(const BTCCReceiptState& previous,
                               const BTCCReceipt& receipt) noexcept
{
    return previous.IsStructurallyValid() &&
           receipt.IsStructurallyValid() && !receipt.IsNull() &&
           receipt.accepted_cursor != previous.cursor;
}

bool IsExactBTCCReceiptTransition(const BTCCReceiptState& previous,
                                  const BTCCReceipt& receipt,
                                  BTCCAdvance advance) noexcept
{
    if (!previous.IsStructurallyValid() ||
        !receipt.IsStructurallyValid() || receipt.IsNull()) {
        return false;
    }
    if (advance == BTCCAdvance::KEEP) {
        return !previous.cursor.IsNull() &&
               receipt.accepted_cursor == previous.cursor;
    }
    return advance == BTCCAdvance::ADVANCE &&
           BTCCReceiptAdvancesCursor(previous, receipt) &&
           (previous.cursor.IsNull() ||
            receipt.accepted_cursor.sys_height >
                previous.cursor.sys_height) &&
           receipt.accepted_cursor.sys_height ==
               receipt.chainlock_target_height;
}

bool IsBTCCCandidateHeight(const BTCCScheduleConfig& config, int32_t height) noexcept
{
    return config.IsValid() && height >= config.candidate_origin &&
           (static_cast<int64_t>(height) - config.candidate_origin) %
                   config.candidate_period ==
               0;
}

bool IsBTCPREVCommitmentHeight(const Consensus::Params& consensus,
                               int32_t height) noexcept
{
    // Genesis has no AuxPoW parent and cannot carry an authenticated Bitcoin
    // prevhash. A regtest origin of zero still schedules the first usable
    // candidate at the next period; height zero deterministically contributes
    // no candidate and therefore yields a null receipt at its carrier slot.
    return height > 0 &&
           IsBTCCCandidateHeight(GetBTCCScheduleConfig(consensus), height);
}

bool ValidateBTCCursorTransition(
    const BTCCScheduleConfig& config,
    const CBlockIndex& target,
    const BTCCursor& previous,
    const BTCCursor& accepted,
    BTCCAdvance advance,
    BTCCValidationError* error)
{
    SetError(error, BTCCValidationError::NONE);
    if (!config.IsValid()) {
        SetError(error, BTCCValidationError::INVALID_CONFIG);
        return false;
    }
    if (target.nHeight < 0 || target.GetBlockHash().IsNull()) {
        SetError(error, BTCCValidationError::INVALID_TARGET);
        return false;
    }
    if (advance != BTCCAdvance::KEEP && advance != BTCCAdvance::ADVANCE) {
        SetError(error, BTCCValidationError::INVALID_ADVANCE_FLAG);
        return false;
    }

    if (!previous.IsStructurallyValid()) {
        SetError(error, BTCCValidationError::INVALID_PREVIOUS_CURSOR);
        return false;
    }
    if (!previous.IsNull() &&
        !ValidateCursorOnBranch(target, previous,
                                BTCCValidationError::INVALID_PREVIOUS_CURSOR, error)) {
        return false;
    }

    if (advance == BTCCAdvance::KEEP) {
        if (accepted != previous) {
            SetError(error, BTCCValidationError::KEEP_MISMATCH);
            return false;
        }
        return true;
    }

    if (!accepted.IsStructurallyValid() || accepted.IsNull()) {
        SetError(error, BTCCValidationError::INVALID_CURSOR);
        return false;
    }
    if ((!previous.IsNull() && accepted.sys_height <= previous.sys_height) ||
        !IsBTCCCandidateHeight(config, accepted.sys_height)) {
        SetError(error, !previous.IsNull() && accepted.sys_height <= previous.sys_height
                            ? BTCCValidationError::NON_MONOTONIC_ADVANCE
                            : BTCCValidationError::UNSCHEDULED_CANDIDATE);
        return false;
    }
    return ValidateCursorOnBranch(target, accepted,
                                  BTCCValidationError::INVALID_CURSOR, error);
}

std::optional<BTCCSelection> SelectBTCCForChainLock(
    const BTCCScheduleConfig& config,
    const CBlockIndex& target,
    const BTCCursor& previous,
    BTCCValidationError* error)
{
    SetError(error, BTCCValidationError::NONE);
    if (!config.IsValid()) {
        SetError(error, BTCCValidationError::INVALID_CONFIG);
        return std::nullopt;
    }
    if (target.nHeight < 0 || target.GetBlockHash().IsNull()) {
        SetError(error, BTCCValidationError::INVALID_TARGET);
        return std::nullopt;
    }

    // KEEP also proves that the predecessor cursor is still on this branch.
    if (!ValidateBTCCursorTransition(config, target, previous, previous,
                                      BTCCAdvance::KEEP, error)) {
        return std::nullopt;
    }
    if (target.nHeight < config.candidate_origin ||
        !IsBTCCCandidateHeight(config, target.nHeight)) {
        return BTCCSelection{previous, BTCCAdvance::KEEP};
    }

    const int32_t candidate_height{target.nHeight};
    if ((!previous.IsNull() && candidate_height <= previous.sys_height)) {
        return BTCCSelection{previous, BTCCAdvance::KEEP};
    }

    const CBlockIndex* candidate{target.GetAncestor(candidate_height)};
    if (candidate == nullptr) {
        SetError(error, BTCCValidationError::MISSING_ANCESTOR);
        return std::nullopt;
    }
    if (candidate->btcpPrevCommitment.IsNull()) {
        return BTCCSelection{previous, BTCCAdvance::KEEP};
    }

    const BTCCursor cursor{candidate->nHeight, candidate->GetBlockHash(),
                           candidate->btcpPrevCommitment};
    if (!ValidateBTCCursorTransition(config, target, previous, cursor,
                                      BTCCAdvance::ADVANCE, error)) {
        return std::nullopt;
    }
    return BTCCSelection{cursor, BTCCAdvance::ADVANCE};
}

std::optional<int32_t> BTCCSourceHeightForNEVMInjection(
    const BTCCScheduleConfig& config, int32_t current_height) noexcept
{
    if (!config.IsValid() || current_height < static_cast<int32_t>(config.nevm_injection_lag)) {
        return std::nullopt;
    }
    const int64_t source{static_cast<int64_t>(current_height) - config.nevm_injection_lag};
    if (source < 0 || source > std::numeric_limits<int32_t>::max() ||
        !IsBTCCCandidateHeight(config, static_cast<int32_t>(source))) {
        return std::nullopt;
    }
    return static_cast<int32_t>(source);
}

bool IsBTCCReceiptCarrierHeight(const BTCCScheduleConfig& config,
                                int32_t height) noexcept
{
    return BTCCSourceHeightForNEVMInjection(config, height).has_value();
}

bool ValidateBTCCReceiptOnBranch(const BTCCScheduleConfig& config,
                                 const CBlockIndex& carrier,
                                 const BTCCReceipt& receipt)
{
    if (!config.IsValid() ||
        !IsBTCCReceiptCarrierHeight(config, carrier.nHeight) ||
        !receipt.IsStructurallyValid()) {
        return false;
    }
    if (receipt.IsNull()) return true;
    const auto source_height{
        BTCCSourceHeightForNEVMInjection(config, carrier.nHeight)};
    if (!source_height || receipt.chainlock_target_height != *source_height) {
        return false;
    }
    const CBlockIndex* target{
        carrier.GetAncestor(receipt.chainlock_target_height)};
    const CBlockIndex* source{
        carrier.GetAncestor(receipt.accepted_cursor.sys_height)};
    return target != nullptr &&
           target->GetBlockHash() == receipt.chainlock_target_hash &&
           source != nullptr &&
           source->GetBlockHash() == receipt.accepted_cursor.sys_hash &&
           !source->btcpPrevCommitment.IsNull() &&
           source->btcpPrevCommitment == receipt.accepted_cursor.btc_hash;
}

std::optional<BTCCReceiptState> ApplyBTCCReceiptState(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& chainlock_schedule,
    const BTCCScheduleConfig& btcc_schedule,
    int32_t carrier_height,
    const uint256& carrier_hash,
    const BTCCReceiptState& previous,
    const BTCCReceipt& receipt)
{
    if (genesis_hash.IsNull() || carrier_hash.IsNull() ||
        !chainlock_schedule.IsValid() || !btcc_schedule.IsValid() ||
        !IsBTCCReceiptCarrierHeight(btcc_schedule, carrier_height) ||
        !previous.IsStructurallyValid() || !receipt.IsStructurallyValid()) {
        return std::nullopt;
    }
    if (receipt.IsNull()) return previous;
    const auto source_height{
        BTCCSourceHeightForNEVMInjection(btcc_schedule, carrier_height)};
    if (!source_height || receipt.chainlock_target_height != *source_height ||
        !IsEligibleChainLockTarget(
            chainlock_schedule, receipt.chainlock_target_height) ||
        receipt.chainlock_target_height <=
            previous.latest_chainlock_target_height ||
        carrier_height <= previous.latest_receipt_carrier_height) {
        return std::nullopt;
    }
    if (!IsExactBTCCReceiptTransition(
            previous, receipt, BTCCAdvance::KEEP) &&
        !IsExactBTCCReceiptTransition(
            previous, receipt, BTCCAdvance::ADVANCE)) {
        return std::nullopt;
    }
    const auto signing_height{SigningHeightForTarget(
        chainlock_schedule, receipt.chainlock_target_height)};
    if (!signing_height ||
        static_cast<int64_t>(*signing_height) +
                PQ_BTCC_RECEIPT_PROPAGATION_BUFFER !=
            carrier_height) {
        return std::nullopt;
    }

    HashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{PQ_BTCC_RECEIPT_STATE_DOMAIN.data(),
                              PQ_BTCC_RECEIPT_STATE_DOMAIN.size()}));
    writer << genesis_hash << previous.cumulative_hash << carrier_height
           << carrier_hash << receipt;
    return BTCCReceiptState{
        receipt.accepted_cursor, writer.GetHash(),
        receipt.chainlock_target_height, carrier_height};
}

std::optional<BTCCReceipt> ReconstructBTCCReceipt(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& chainlock_schedule,
    const BTCCScheduleConfig& btcc_schedule,
    const CBlockIndex& carrier,
    const BTCCReceiptState& previous,
    const BTCCReceiptState& current,
    const uint256& receipt_logical_id)
{
    if (genesis_hash.IsNull() || !chainlock_schedule.IsValid() ||
        !btcc_schedule.IsValid() || !previous.IsStructurallyValid() ||
        !current.IsStructurallyValid() ||
        !IsBTCCReceiptCarrierHeight(btcc_schedule, carrier.nHeight)) {
        return std::nullopt;
    }

    BTCCReceipt receipt;
    if (!receipt_logical_id.IsNull()) {
        const auto source_height{BTCCSourceHeightForNEVMInjection(
            btcc_schedule, carrier.nHeight)};
        if (!source_height || current.cursor.IsNull() ||
            current.latest_chainlock_target_height != *source_height ||
            current.latest_receipt_carrier_height != carrier.nHeight) {
            return std::nullopt;
        }
        receipt.chainlock_target_height = *source_height;
        const CBlockIndex* target{carrier.GetAncestor(*source_height)};
        if (target == nullptr) return std::nullopt;
        receipt.chainlock_target_hash = target->GetBlockHash();
        receipt.chainlock_logical_id = receipt_logical_id;
        receipt.accepted_cursor = current.cursor;
    }
    if (!ValidateBTCCReceiptOnBranch(btcc_schedule, carrier, receipt)) {
        return std::nullopt;
    }
    const auto applied{ApplyBTCCReceiptState(
        genesis_hash, chainlock_schedule, btcc_schedule, carrier.nHeight,
        carrier.GetBlockHash(), previous, receipt)};
    return applied && *applied == current
               ? std::optional<BTCCReceipt>{receipt}
               : std::nullopt;
}

} // namespace llmq::pq
