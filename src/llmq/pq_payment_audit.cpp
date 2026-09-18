// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit.h>
#include <llmq/pq_roster_beacon.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <limits>

namespace llmq::pq {
namespace {

constexpr int64_t MAX_HEIGHT{std::numeric_limits<int32_t>::max()};

uint64_t SelectionWord(const uint256& hash)
{
    uint64_t value{0};
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        value |= static_cast<uint64_t>(hash.begin()[i]) << (8 * i);
    }
    return value;
}

std::optional<int32_t> FirstJointCandidateAtOrAfter(
    const PaymentAuditScheduleConfig& config, int64_t height) noexcept
{
    if (!config.IsValid() || height < 0 || height > MAX_HEIGHT) {
        return std::nullopt;
    }
    const int64_t origin{config.btcc.candidate_origin};
    const int64_t offset{std::max(height, origin) - origin};
    const int64_t remainder{offset % config.btcc.candidate_period};
    const int64_t candidate{std::max(height, origin) +
                            (remainder == 0
                                 ? 0
                                 : config.btcc.candidate_period - remainder)};
    if (candidate > MAX_HEIGHT) return std::nullopt;
    const int32_t result{static_cast<int32_t>(candidate)};
    return IsBTCCCandidateHeight(config.btcc, result) &&
                   IsEligibleChainLockTarget(config.chainlock, result)
               ? std::optional<int32_t>{result}
               : std::nullopt;
}

std::optional<int32_t> FirstChainLockTargetAtOrAfter(
    const ChainLockScheduleConfig& config, int64_t height) noexcept
{
    if (!config.IsValid() || height < config.epoch_origin ||
        height > MAX_HEIGHT) {
        return std::nullopt;
    }
    const int64_t offset{height - config.epoch_origin};
    const int64_t remainder{offset % config.chainlock_period};
    const int64_t target{height + (remainder == 0
                                       ? 0
                                       : config.chainlock_period - remainder)};
    if (target > MAX_HEIGHT) return std::nullopt;
    const int32_t result{static_cast<int32_t>(target)};
    return IsEligibleChainLockTarget(config, result)
               ? std::optional<int32_t>{result}
               : std::nullopt;
}

std::optional<int32_t> FirstNonBTCCChainLockTargetAtOrAfter(
    const PaymentAuditScheduleConfig& config, int64_t height) noexcept
{
    auto target{FirstChainLockTargetAtOrAfter(config.chainlock, height)};
    if (!target) return std::nullopt;
    if (IsBTCCCandidateHeight(config.btcc, *target)) {
        const int64_t next{static_cast<int64_t>(*target) + PQ_CL_PERIOD};
        if (next > MAX_HEIGHT) return std::nullopt;
        target = static_cast<int32_t>(next);
    }
    return target && IsEligibleChainLockTarget(config.chainlock, *target) &&
                   !IsBTCCCandidateHeight(config.btcc, *target)
               ? target
               : std::nullopt;
}

std::optional<int32_t> FirstCarrierAtOrAfter(
    const BTCCScheduleConfig& config, int64_t height) noexcept
{
    if (!config.IsValid() || height < 0 || height > MAX_HEIGHT) {
        return std::nullopt;
    }
    const int64_t first_carrier{
        static_cast<int64_t>(config.candidate_origin) +
        config.nevm_injection_lag};
    const int64_t start{std::max(height, first_carrier)};
    const int64_t remainder{(start - first_carrier) % config.candidate_period};
    const int64_t carrier{start + (remainder == 0
                                       ? 0
                                       : config.candidate_period - remainder)};
    if (carrier > MAX_HEIGHT) return std::nullopt;
    const int32_t result{static_cast<int32_t>(carrier)};
    return IsBTCCReceiptCarrierHeight(config, result)
               ? std::optional<int32_t>{result}
               : std::nullopt;
}

std::optional<int32_t> SealHeightForEpoch(
    const PaymentAuditScheduleConfig& config, uint32_t epoch) noexcept
{
    const auto base{EpochBaseHeight(config.chainlock, epoch)};
    const auto end{EpochEndHeightExclusive(config.chainlock, epoch)};
    const auto first{base
                         ? FirstJointCandidateAtOrAfter(config, *base)
                         : std::nullopt};
    if (!base || !end || !first || *first >= *end) return std::nullopt;
    const int64_t last_response{
        static_cast<int64_t>(*first) +
        static_cast<int64_t>(PAYMENT_AUDIT_ROW_COUNT - 1) *
            PAYMENT_AUDIT_ROW_PERIOD};
    const int64_t anchor{last_response +
                         PAYMENT_AUDIT_ROW_DEADLINE_DELAY +
                         PAYMENT_AUDIT_ROW_PERIOD};
    if (anchor > MAX_HEIGHT || anchor >= *end) return std::nullopt;
    return FirstNonBTCCChainLockTargetAtOrAfter(
        config, anchor + PAYMENT_AUDIT_SEAL_DELAY);
}

} // namespace

bool PaymentAuditHave::IsStructurallyValid() const noexcept
{
    return version == PAYMENT_AUDIT_VERSION &&
           row_index < PAYMENT_AUDIT_ROW_COUNT && response_height >= 0 &&
           !response_chainlock_logical_id.IsNull() &&
           !subject_descriptor_hash.IsNull();
}

bool PaymentAuditResponse::IsStructurallyValid() const noexcept
{
    return version == PAYMENT_AUDIT_VERSION &&
           row_index < PAYMENT_AUDIT_ROW_COUNT &&
           !subject_descriptor_hash.IsNull() &&
           response.IsStructurallyValid() &&
           response.GetStatement().btcc_advance == BTCCAdvance::ADVANCE;
}

bool PaymentAuditScheduleConfig::IsValid() const noexcept
{
    if (!chainlock.IsValid() || !btcc.IsValid()) return false;
    if (btcc.candidate_period != PQ_BTCC_CANDIDATE_PERIOD) {
        return false;
    }
    return IsEligibleChainLockTarget(chainlock, btcc.candidate_origin) &&
           IsBTCCCandidateHeight(btcc, btcc.candidate_origin);
}

bool PaymentAuditEpochSchedule::IsStructurallyValid(
    const PaymentAuditScheduleConfig& config) const noexcept
{
    if (!config.IsValid()) return false;
    const auto base{EpochBaseHeight(config.chainlock, epoch)};
    const auto end{EpochEndHeightExclusive(config.chainlock, epoch)};
    if (!base || !end) return false;
    const auto expected_first{FirstJointCandidateAtOrAfter(config, *base)};
    if (!expected_first || *expected_first >= *end) return false;

    for (std::size_t row{0}; row < rows.size(); ++row) {
        const int64_t response{
            static_cast<int64_t>(*expected_first) +
            static_cast<int64_t>(row) * PAYMENT_AUDIT_ROW_PERIOD};
        const int64_t deadline{response + PAYMENT_AUDIT_ROW_DEADLINE_DELAY};
        if (deadline > MAX_HEIGHT || rows[row].response_height != response ||
            rows[row].deadline_height != deadline || deadline >= *end ||
            !IsBTCCCandidateHeight(config.btcc,
                                   rows[row].response_height) ||
            !IsEligibleChainLockTarget(config.chainlock,
                                       rows[row].response_height) ||
            !IsEligibleChainLockTarget(config.chainlock,
                                       rows[row].deadline_height)) {
            return false;
        }
    }

    const int64_t expected_anchor{
        static_cast<int64_t>(rows.back().deadline_height) +
        PAYMENT_AUDIT_ROW_PERIOD};
    if (expected_anchor > MAX_HEIGHT || anchor_height != expected_anchor ||
        anchor_height >= *end ||
        !IsBTCCCandidateHeight(config.btcc, anchor_height) ||
        !IsEligibleChainLockTarget(config.chainlock, anchor_height)) {
        return false;
    }

    const auto expected_seal{FirstNonBTCCChainLockTargetAtOrAfter(
        config,
        static_cast<int64_t>(anchor_height) +
            PAYMENT_AUDIT_SEAL_DELAY)};
    const auto expected_carrier{expected_seal
                                    ? FirstCarrierAtOrAfter(
                                          config.btcc,
                                          static_cast<int64_t>(*expected_seal) +
                                              PAYMENT_AUDIT_RECEIPT_DELAY)
                                    : std::nullopt};
    if (!expected_seal || !expected_carrier ||
        epoch == std::numeric_limits<uint32_t>::max() ||
        *expected_seal != seal_height ||
        *expected_carrier != carrier_start_height ||
        carrier_start_height >= carrier_end_height_exclusive ||
        !IsBTCCReceiptCarrierHeight(config.btcc,
                                    carrier_start_height)) {
        return false;
    }

    const auto next_seal{SealHeightForEpoch(config, epoch + 1)};
    if (!next_seal ||
        carrier_end_height_exclusive != *next_seal ||
        carrier_end_height_exclusive <= carrier_start_height) {
        return false;
    }
    return true;
}

std::optional<PaymentAuditEpochSchedule>
BuildPaymentAuditEpochSchedule(const PaymentAuditScheduleConfig& config,
                               uint32_t epoch) noexcept
{
    if (!config.IsValid()) return std::nullopt;
    const auto base{EpochBaseHeight(config.chainlock, epoch)};
    const auto end{EpochEndHeightExclusive(config.chainlock, epoch)};
    if (!base || !end) return std::nullopt;
    const auto first{FirstJointCandidateAtOrAfter(config, *base)};
    if (!first || *first >= *end) return std::nullopt;

    PaymentAuditEpochSchedule schedule;
    schedule.epoch = epoch;
    for (std::size_t row{0}; row < schedule.rows.size(); ++row) {
        const int64_t response{static_cast<int64_t>(*first) +
                               static_cast<int64_t>(row) *
                                   PAYMENT_AUDIT_ROW_PERIOD};
        const int64_t deadline{response + PAYMENT_AUDIT_ROW_DEADLINE_DELAY};
        if (deadline > MAX_HEIGHT) return std::nullopt;
        schedule.rows[row] = {static_cast<int32_t>(response),
                              static_cast<int32_t>(deadline)};
    }
    const int64_t anchor{
        static_cast<int64_t>(schedule.rows.back().deadline_height) +
        PAYMENT_AUDIT_ROW_PERIOD};
    if (anchor > MAX_HEIGHT) return std::nullopt;
    schedule.anchor_height = static_cast<int32_t>(anchor);
    const auto seal{FirstNonBTCCChainLockTargetAtOrAfter(
        config, anchor + PAYMENT_AUDIT_SEAL_DELAY)};
    const auto carrier{seal ? FirstCarrierAtOrAfter(
                                  config.btcc,
                                  static_cast<int64_t>(*seal) +
                                      PAYMENT_AUDIT_RECEIPT_DELAY)
                            : std::nullopt};
    const auto carrier_end{
        epoch < std::numeric_limits<uint32_t>::max()
            ? SealHeightForEpoch(config, epoch + 1)
            : std::nullopt};
    if (!seal || !carrier || !carrier_end) return std::nullopt;
    schedule.seal_height = *seal;
    schedule.carrier_start_height = *carrier;
    schedule.carrier_end_height_exclusive = *carrier_end;
    if (!schedule.IsStructurallyValid(config)) return std::nullopt;
    return schedule;
}

std::optional<int32_t> PaymentAuditProtectionCarrierEnd(
    const PaymentAuditScheduleConfig& config,
    int32_t owner_height) noexcept
{
    const auto owner_epoch{EpochForHeight(config.chainlock, owner_height)};
    if (!owner_epoch) return std::nullopt;
    for (uint32_t offset{1};
         offset <= PAYMENT_AUDIT_CARRIER_EPOCH_LOOKBACK; ++offset) {
        if (*owner_epoch < offset) continue;
        const auto schedule{BuildPaymentAuditEpochSchedule(
            config, *owner_epoch - offset)};
        if (schedule && owner_height >= schedule->seal_height &&
            owner_height < schedule->carrier_end_height_exclusive) {
            return schedule->carrier_end_height_exclusive;
        }
    }
    return std::nullopt;
}

std::optional<uint8_t> PaymentAuditLeafIndex(
    const PaymentAuditScheduleConfig& config,
    uint32_t subject_epoch,
    int32_t seal_height,
    uint32_t child_epoch) noexcept
{
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(config, subject_epoch)};
    const auto seal_epoch{EpochForHeight(config.chainlock, seal_height)};
    const auto active_epochs{
        ActiveEpochsAtHeight(config.chainlock, seal_height)};
    if (!audit_schedule || audit_schedule->seal_height != seal_height ||
        !seal_epoch || subject_epoch == std::numeric_limits<uint32_t>::max() ||
        *seal_epoch != subject_epoch + 1 || !active_epochs) {
        return std::nullopt;
    }
    for (std::size_t slot{0}; slot < active_epochs->size(); ++slot) {
        if ((*active_epochs)[slot].epoch != child_epoch) continue;
        if (child_epoch > *seal_epoch ||
            *seal_epoch - child_epoch >= ACTIVE_QUORUMS) {
            return std::nullopt;
        }
        const uint16_t leaf{
            static_cast<uint16_t>(SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE +
                                  (*seal_epoch - child_epoch))};
        if (leaf >= SCHEDULED_WOTS_USAGE_CAP) return std::nullopt;
        return static_cast<uint8_t>(leaf);
    }
    return std::nullopt;
}

bool PaymentAuditCarrierWindow::Contains(int32_t height) const noexcept
{
    return start_height >= 0 && end_height_exclusive > start_height &&
           height >= start_height && height < end_height_exclusive;
}

std::optional<PaymentAuditCarrierWindow>
BuildPaymentAuditCarrierWindow(const PaymentAuditScheduleConfig& config,
                               uint32_t epoch) noexcept
{
    const auto schedule{BuildPaymentAuditEpochSchedule(config, epoch)};
    if (!schedule) return std::nullopt;
    return PaymentAuditCarrierWindow{epoch, schedule->carrier_start_height,
                                     schedule->carrier_end_height_exclusive};
}

std::optional<uint32_t> PaymentAuditReceiptSlotEpoch(
    const PaymentAuditScheduleConfig& config, int32_t height) noexcept
{
    if (!config.IsValid() ||
        !IsBTCCReceiptCarrierHeight(config.btcc, height)) {
        return std::nullopt;
    }
    const auto carrier_epoch{EpochForHeight(config.chainlock, height)};
    if (!carrier_epoch) return std::nullopt;
    for (uint32_t offset{1};
         offset <= PAYMENT_AUDIT_CARRIER_EPOCH_LOOKBACK; ++offset) {
        if (*carrier_epoch < offset) continue;
        const uint32_t subject_epoch{*carrier_epoch - offset};
        const auto window{
            BuildPaymentAuditCarrierWindow(config, subject_epoch)};
        if (window && window->Contains(height)) return subject_epoch;
    }
    return std::nullopt;
}

bool PaymentAuditSeedPoint::IsStructurallyValid() const noexcept
{
    return target_height >= 0 && !chainlock_logical_id.IsNull() &&
           accepted_cursor.IsStructurallyValid() &&
           !accepted_cursor.IsNull() &&
           accepted_cursor.sys_height == target_height &&
           advance == BTCCAdvance::ADVANCE;
}

std::optional<PaymentAuditSeedPoint>
PaymentAuditSeedPointFromBTCCReceipt(const BTCCReceipt& receipt) noexcept
{
    if (!receipt.IsStructurallyValid() || receipt.IsNull() ||
        receipt.chainlock_target_height !=
            receipt.accepted_cursor.sys_height ||
        receipt.chainlock_target_hash != receipt.accepted_cursor.sys_hash) {
        return std::nullopt;
    }
    PaymentAuditSeedPoint seed_point{
        receipt.chainlock_target_height, receipt.chainlock_logical_id,
        receipt.accepted_cursor, BTCCAdvance::ADVANCE};
    return seed_point.IsStructurallyValid()
               ? std::optional<PaymentAuditSeedPoint>{seed_point}
               : std::nullopt;
}

std::optional<BTCCReceipt> BTCCReceiptFromPaymentAuditSeedPoint(
    const PaymentAuditSeedPoint& seed_point) noexcept
{
    if (!seed_point.IsStructurallyValid()) return std::nullopt;
    BTCCReceipt receipt;
    receipt.chainlock_target_height = seed_point.target_height;
    receipt.chainlock_target_hash = seed_point.accepted_cursor.sys_hash;
    receipt.chainlock_logical_id = seed_point.chainlock_logical_id;
    receipt.accepted_cursor = seed_point.accepted_cursor;
    return receipt.IsStructurallyValid()
               ? std::optional<BTCCReceipt>{receipt}
               : std::nullopt;
}

bool PaymentAuditSeed::IsStructurallyValid() const noexcept
{
    return anchor.IsStructurallyValid() && anchor_btc_height >= 0 &&
           future_btc_height >= 0 &&
           static_cast<int64_t>(anchor_btc_height) +
                   PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA ==
               future_btc_height &&
           !future_btc_hash.IsNull() &&
           future_btc_hash != anchor.accepted_cursor.btc_hash;
}

uint256 GetPaymentAuditSelectionHash(const uint256& genesis_hash,
                                     const uint256& subject_descriptor_hash,
                                     const PaymentAuditSeed& seed)
{
    return TaggedHash(PAYMENT_AUDIT_SELECTION_DOMAIN, genesis_hash,
                      seed.epoch, subject_descriptor_hash,
                      seed.anchor, seed.anchor_btc_height,
                      seed.anchor.accepted_cursor.btc_hash,
                      seed.future_btc_height, seed.future_btc_hash);
}

std::optional<PaymentAuditRound> SelectPaymentAuditRound(
    const PaymentAuditScheduleConfig& config,
    const PaymentAuditEpochSchedule& schedule,
    const uint256& genesis_hash,
    const uint256& subject_descriptor_hash,
    const PaymentAuditSeed& seed) noexcept
{
    if (genesis_hash.IsNull() || subject_descriptor_hash.IsNull() ||
        !schedule.IsStructurallyValid(config) ||
        !seed.IsStructurallyValid() || seed.epoch != schedule.epoch ||
        seed.anchor.target_height != schedule.anchor_height) {
        return std::nullopt;
    }
    const uint256 selection{GetPaymentAuditSelectionHash(
        genesis_hash, subject_descriptor_hash, seed)};
    const uint8_t row{static_cast<uint8_t>(
        SelectionWord(selection) % PAYMENT_AUDIT_ROW_COUNT)};
    return PaymentAuditRound{
        seed,
        row,
        schedule.rows[row].response_height,
        schedule.rows[row].deadline_height,
        schedule.seal_height,
        schedule.carrier_start_height,
        schedule.carrier_end_height_exclusive};
}

bool PaymentAuditCommitment::IsStructurallyValid() const noexcept
{
    if (version != PAYMENT_AUDIT_VERSION ||
        child_profile != CHILD_SCHEDULED_WOTS_SHAKE_128_V1 ||
        !seed.IsStructurallyValid() ||
        selected_row >= PAYMENT_AUDIT_ROW_COUNT || response_height < 0 ||
        deadline_height < 0 ||
        static_cast<int64_t>(response_height) +
                PAYMENT_AUDIT_ROW_DEADLINE_DELAY !=
            deadline_height ||
        deadline_height >= seed.anchor.target_height ||
        response_chainlock_logical_id.IsNull() ||
        response_advance != BTCCAdvance::ADVANCE || seal_height < 0 ||
        static_cast<int64_t>(response_height) +
                PAYMENT_AUDIT_ROW_DEADLINE_DELAY >=
            seed.anchor.target_height ||
        seed.anchor.target_height >= seal_height ||
        subject_epoch != seed.epoch ||
        subject_quorum_base_hash.IsNull() ||
        subject_descriptor_hash.IsNull() ||
        CountSet(subject_valid_members) < QUORUM_MIN_VALID ||
        previous_probation_state_hash.IsNull()) {
        return false;
    }
    return true;
}

bool PaymentAuditStatement::IsStructurallyValid() const noexcept
{
    const RosterBeaconSeed* subject_beacon{FindRosterBeaconSeed(
        seal_statement.roster_beacons.active,
        commitment.subject_epoch)};
    return commitment.IsStructurallyValid() &&
           seal_statement.IsStructurallyValid() && subject_beacon != nullptr &&
           subject_beacon->anchor_kind == RosterBeaconAnchorKind::NORMAL &&
           seal_statement.height == commitment.seal_height &&
           seal_statement.payment_probation_state_hash ==
               commitment.previous_probation_state_hash;
}

bool PaymentAuditShareTranscript::IsStructurallyValid() const noexcept
{
    return statement.IsStructurallyValid() && !quorum_base_hash.IsNull() &&
           member_index < QUORUM_SIZE && !member_pro_tx_hash.IsNull() &&
           IsQuorumBitmapSubset(
               reporter_observed_members,
               statement.commitment.subject_valid_members);
}

bool PaymentAuditShare::IsStructurallyValid() const noexcept
{
    return transcript.IsStructurallyValid() &&
           authenticated_signature.IsStructurallyValid();
}

uint256 PaymentAuditShare::GetId(const uint256& genesis_hash) const
{
    return GetPaymentAuditShareId(genesis_hash, *this);
}

bool PaymentAuditReportWitness::IsStructurallyValid(
    const QuorumBitmap& subject_valid_members) const noexcept
{
    return IsQuorumBitmapSubset(observed_members, subject_valid_members) &&
           authenticated_signature.IsStructurallyValid();
}

bool FinalPaymentAudit::IsStructurallyValid() const noexcept
{
    if (!statement.IsStructurallyValid() ||
        !IsSelectedQuorumMask(selected_quorum_mask) ||
        report_witnesses.size() != PAYMENT_AUDIT_SIGNATURE_COUNT) {
        return false;
    }
    std::size_t selected{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const bool is_selected{
            (selected_quorum_mask & (uint8_t{1} << slot)) != 0};
        const std::size_t count{CountSet(signer_bitmaps[slot])};
        if ((is_selected && count != QUORUM_THRESHOLD) ||
            (!is_selected && count != 0)) {
            return false;
        }
        selected += is_selected ? 1 : 0;
    }
    return selected == REQUIRED_QUORUMS &&
           std::all_of(
               report_witnesses.begin(), report_witnesses.end(),
               [&](const auto& witness) {
                   return witness.IsStructurallyValid(
                       statement.commitment.subject_valid_members);
               });
}

uint256 FinalPaymentAudit::GetLogicalId(const uint256& genesis_hash) const
{
    return GetPaymentAuditLogicalId(genesis_hash, statement);
}

uint256 FinalPaymentAudit::GetWitnessId(const uint256& genesis_hash) const
{
    return GetPaymentAuditWitnessId(genesis_hash, *this);
}

std::optional<std::size_t> FinalPaymentAudit::SignatureOffset(
    uint8_t quorum_slot, uint16_t member_index) const noexcept
{
    if (quorum_slot >= ACTIVE_QUORUMS || member_index >= QUORUM_SIZE ||
        !IsStructurallyValid() ||
        (selected_quorum_mask & (uint8_t{1} << quorum_slot)) == 0 ||
        !IsQuorumMemberSet(signer_bitmaps[quorum_slot], member_index)) {
        return std::nullopt;
    }
    std::size_t offset{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            if (!IsQuorumMemberSet(signer_bitmaps[slot], member)) continue;
            if (slot == quorum_slot && member == member_index) return offset;
            ++offset;
        }
    }
    return std::nullopt;
}

bool PaymentAuditReceipt::IsNull() const noexcept
{
    return version == PAYMENT_AUDIT_RECEIPT_VERSION && has_audit == 0 &&
           epoch == 0 && seal_height == -1 && seal_block_hash.IsNull() &&
           carrier_height == -1 && audit_logical_id.IsNull() &&
           audit_witness_id.IsNull() && commitment_hash.IsNull() &&
           result_hash.IsNull() &&
           next_probation_state_hash.IsNull() &&
           subject_roster_beacon == RosterBeaconSeed{} &&
           online_members == QuorumBitmap{};
}

bool PaymentAuditReceipt::IsStructurallyValid() const noexcept
{
    if (version != PAYMENT_AUDIT_RECEIPT_VERSION || has_audit > 1) {
        return false;
    }
    if (has_audit == 0) return IsNull();
    return seal_height >= 0 &&
           static_cast<int64_t>(seal_height) +
                   PAYMENT_AUDIT_RECEIPT_DELAY <=
               carrier_height &&
           !seal_block_hash.IsNull() && !audit_logical_id.IsNull() &&
           !audit_witness_id.IsNull() && !commitment_hash.IsNull() &&
           !result_hash.IsNull() &&
           !next_probation_state_hash.IsNull() &&
           subject_roster_beacon.IsReady() &&
           subject_roster_beacon.anchor_kind ==
               RosterBeaconAnchorKind::NORMAL &&
           subject_roster_beacon.epoch == epoch;
}

bool IsPaymentAuditCandidateCompatible(
    const FinalPaymentAudit& candidate,
    const PaymentAuditStatement& active_statement) noexcept
{
    return active_statement.IsStructurallyValid() &&
           candidate.IsStructurallyValid() &&
           candidate.statement == active_statement;
}

uint256 GetPaymentAuditCommitmentHash(
    const uint256& genesis_hash,
    const PaymentAuditCommitment& commitment)
{
    return TaggedHash(PAYMENT_AUDIT_COMMITMENT_DOMAIN, genesis_hash,
                      commitment);
}

uint256 GetPaymentAuditDescriptorHash(
    const uint256& genesis_hash,
    const QuorumDescriptor& descriptor)
{
    return TaggedHash(PAYMENT_AUDIT_DESCRIPTOR_DOMAIN, genesis_hash,
                      descriptor);
}

std::optional<PaymentAuditClassification>
ClassifyPaymentAuditReports(const FinalPaymentAudit& audit) noexcept
{
    if (!audit.IsStructurallyValid()) return std::nullopt;

    PaymentAuditClassification classification;
    std::size_t offset{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((audit.selected_quorum_mask & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        std::array<uint16_t, QUORUM_SIZE> positive_reports{};
        for (std::size_t reporter{0}; reporter < QUORUM_SIZE; ++reporter) {
            if (!IsQuorumMemberSet(audit.signer_bitmaps[slot], reporter)) continue;
            if (offset >= audit.report_witnesses.size()) return std::nullopt;
            const auto& observed{
                audit.report_witnesses[offset++].observed_members};
            for (std::size_t subject{0}; subject < QUORUM_SIZE; ++subject) {
                if (IsQuorumMemberSet(observed, subject)) {
                    ++positive_reports[subject];
                }
            }
        }
        for (std::size_t subject{0}; subject < QUORUM_SIZE; ++subject) {
            if (positive_reports[subject] >=
                PAYMENT_AUDIT_REPORT_ONLINE_THRESHOLD) {
                SetQuorumMember(
                    classification.online_by_reporter_roster[slot], subject);
                SetQuorumMember(classification.online_members, subject);
            }
        }
    }
    if (offset != audit.report_witnesses.size()) return std::nullopt;

    const auto& valid{audit.statement.commitment.subject_valid_members};
    for (std::size_t subject{0}; subject < QUORUM_SIZE; ++subject) {
        if (IsQuorumMemberSet(valid, subject) &&
            !IsQuorumMemberSet(classification.online_members, subject)) {
            SetQuorumMember(classification.missed_members, subject);
        }
    }
    classification.online_count = static_cast<uint16_t>(
        CountSet(classification.online_members));
    classification.conclusive =
        classification.online_count >= QUORUM_MIN_VALID;
    return classification;
}

uint256 GetPaymentAuditResultHash(
    const uint256& genesis_hash,
    const FinalPaymentAudit& audit,
    const PaymentAuditClassification& classification)
{
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PAYMENT_AUDIT_RESULT_DOMAIN);
    writer << genesis_hash << audit.selected_quorum_mask;
    for (const auto& bitmap : audit.signer_bitmaps) writer << bitmap;
    writer << static_cast<uint16_t>(audit.report_witnesses.size());
    for (const auto& witness : audit.report_witnesses) {
        writer << witness.observed_members;
    }
    writer << classification.online_members
           << classification.missed_members
           << static_cast<uint8_t>(classification.conclusive);
    return writer.GetHash();
}

uint256 GetPaymentAuditShareHash(
    const uint256& genesis_hash,
    const PaymentAuditShareTranscript& transcript)
{
    return TaggedHash(PAYMENT_AUDIT_SHARE_DOMAIN, genesis_hash, transcript);
}

uint256 GetPaymentAuditShareId(const uint256& genesis_hash,
                               const PaymentAuditShare& share)
{
    return TaggedHash(PAYMENT_AUDIT_SHARE_ID_DOMAIN, genesis_hash, share);
}

uint256 GetPaymentAuditLogicalId(const uint256& genesis_hash,
                                 const PaymentAuditStatement& statement)
{
    return TaggedHash(PAYMENT_AUDIT_LOGICAL_ID_DOMAIN, genesis_hash,
                      statement);
}

uint256 GetPaymentAuditWitnessId(const uint256& genesis_hash,
                                 const FinalPaymentAudit& audit)
{
    return TaggedHash(PAYMENT_AUDIT_WITNESS_ID_DOMAIN, genesis_hash, audit);
}

std::optional<PaymentAuditReceiptState> ApplyPaymentAuditReceipt(
    const uint256& genesis_hash,
    const PaymentAuditReceiptState& previous,
    const PaymentAuditReceipt& receipt) noexcept
{
    if (genesis_hash.IsNull() || !previous.IsStructurallyValid() ||
        !receipt.IsStructurallyValid()) {
        return std::nullopt;
    }
    if (receipt.IsNull()) return previous;
    if (!previous.cursor.IsNull() &&
        (receipt.epoch <= previous.cursor.epoch ||
         receipt.carrier_height <= previous.cursor.carrier_height)) {
        return std::nullopt;
    }
    CHashWriter writer{SER_GETHASH, 0};
    WriteDomain(writer, PAYMENT_AUDIT_RECEIPT_STATE_DOMAIN);
    writer << genesis_hash << previous << receipt;
    PaymentAuditReceiptState next{
        PaymentAuditReceiptCursor{receipt.carrier_height, receipt.epoch,
                                  receipt.seal_block_hash,
                                  receipt.audit_logical_id,
                                  receipt.audit_witness_id},
        writer.GetHash()};
    if (!next.IsStructurallyValid()) return std::nullopt;
    return next;
}

} // namespace llmq::pq

namespace {

struct PaymentAuditTailLayout {
    std::size_t audit_marker_offset{0};
    std::size_t btcc_marker_offset{0};
};

std::optional<PaymentAuditTailLayout> LocatePaymentAuditTail(
    const std::vector<unsigned char>& data)
{
    constexpr std::size_t AUDIT_SEGMENT_SIZE{
        sizeof(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES) +
        llmq::pq::PaymentAuditReceipt::WIRE_SIZE};
    constexpr std::size_t BTCC_SEGMENT_SIZE{
        sizeof(BTCC_RECEIPT_MAGIC_BYTES) +
        llmq::pq::BTCCReceipt::WIRE_SIZE};
    constexpr std::size_t BTCPREV_SEGMENT_SIZE{
        sizeof(BTCPREV_MAGIC_BYTES) + 32};

    std::optional<PaymentAuditTailLayout> found;
    for (const std::size_t trailing_btcprev :
         {std::size_t{0}, BTCPREV_SEGMENT_SIZE}) {
        const std::size_t suffix_size{
            AUDIT_SEGMENT_SIZE + BTCC_SEGMENT_SIZE +
            trailing_btcprev};
        if (data.size() < suffix_size) continue;
        const std::size_t audit_offset{data.size() - suffix_size};
        const std::size_t btcc_offset{
            audit_offset + AUDIT_SEGMENT_SIZE};
        if (!std::equal(
                std::begin(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
                std::end(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
                data.begin() + audit_offset) ||
            !std::equal(std::begin(BTCC_RECEIPT_MAGIC_BYTES),
                        std::end(BTCC_RECEIPT_MAGIC_BYTES),
                        data.begin() + btcc_offset)) {
            continue;
        }
        if (trailing_btcprev != 0 &&
            !std::equal(std::begin(BTCPREV_MAGIC_BYTES),
                        std::end(BTCPREV_MAGIC_BYTES),
                        data.end() - BTCPREV_SEGMENT_SIZE)) {
            continue;
        }
        // Two syntactically valid suffix starts would give the same bytes
        // competing consensus interpretations.
        if (found) return std::nullopt;
        found = PaymentAuditTailLayout{audit_offset, btcc_offset};
    }
    return found;
}

} // namespace

bool ExtractPaymentAuditReceipt(
    const CBlock& block, llmq::pq::PaymentAuditReceipt& receipt)
{
    if (block.vtx.empty() || !block.vtx[0]) return false;
    std::vector<unsigned char> data;
    int output_index{-1};
    if (!GetSyscoinData(*block.vtx[0], data, output_index)) return false;

    const auto layout{LocatePaymentAuditTail(data)};
    if (!layout) return false;
    // The following fixed suffix is part of the audit carrier grammar, not
    // opaque trailing bytes. Reuse the BTCC decoder so its optional-BTCPREV
    // and ambiguity rules stay identical.
    llmq::pq::BTCCReceipt ignored_btcc;
    if (!ExtractBTCCReceipt(block, ignored_btcc)) return false;

    try {
        const Span<const unsigned char> payload{
            data.data() + layout->audit_marker_offset +
                sizeof(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
            llmq::pq::PaymentAuditReceipt::WIRE_SIZE};
        SpanReader reader{SER_NETWORK, PROTOCOL_VERSION, payload};
        reader >> receipt;
        return reader.empty() && receipt.IsStructurallyValid();
    } catch (const std::exception&) {
        return false;
    }
}

bool HasPaymentAuditReceiptCommitment(const CBlock& block)
{
    if (block.vtx.empty() || !block.vtx[0]) return false;
    std::vector<unsigned char> data;
    int output_index{-1};
    if (!GetSyscoinData(*block.vtx[0], data, output_index)) return false;
    constexpr std::size_t AUDIT_SEGMENT_SIZE{
        sizeof(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES) +
        llmq::pq::PaymentAuditReceipt::WIRE_SIZE};
    constexpr std::size_t BTCC_SEGMENT_SIZE{
        sizeof(BTCC_RECEIPT_MAGIC_BYTES) +
        llmq::pq::BTCCReceipt::WIRE_SIZE};
    constexpr std::size_t BTCPREV_SEGMENT_SIZE{
        sizeof(BTCPREV_MAGIC_BYTES) + 32};
    constexpr std::size_t MIN_TAIL_SIZE{
        AUDIT_SEGMENT_SIZE + BTCC_SEGMENT_SIZE};
    constexpr std::size_t MAX_TAIL_SIZE{
        MIN_TAIL_SIZE + BTCPREV_SEGMENT_SIZE};
    if (data.size() < MIN_TAIL_SIZE) return false;
    const std::size_t first_offset{
        data.size() > MAX_TAIL_SIZE ? data.size() - MAX_TAIL_SIZE : 0};
    const std::size_t last_offset{data.size() - MIN_TAIL_SIZE};
    for (std::size_t offset{first_offset}; offset <= last_offset; ++offset) {
        const std::size_t btcc_offset{offset + AUDIT_SEGMENT_SIZE};
        if (std::equal(
                std::begin(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
                std::end(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
                data.begin() + offset) &&
            std::equal(std::begin(BTCC_RECEIPT_MAGIC_BYTES),
                       std::end(BTCC_RECEIPT_MAGIC_BYTES),
                       data.begin() + btcc_offset)) {
            return true;
        }
    }
    return false;
}
