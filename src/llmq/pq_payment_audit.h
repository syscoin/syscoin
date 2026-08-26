// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_H

#include <llmq/pq_btcc.h>
#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_chainlock_types.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

class CBlock;

inline constexpr uint8_t PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES[4]{
    'p', 'q', 'a', 'r'};

namespace llmq::pq {

inline constexpr uint16_t PAYMENT_AUDIT_VERSION{1};
inline constexpr uint16_t PAYMENT_AUDIT_RECEIPT_VERSION{1};
inline constexpr std::size_t PAYMENT_AUDIT_ROW_COUNT{24};
inline constexpr uint32_t PAYMENT_AUDIT_ROW_PERIOD{
    PQ_BTCC_CANDIDATE_PERIOD};
inline constexpr uint32_t PAYMENT_AUDIT_ROW_DEADLINE_DELAY{20};
inline constexpr uint32_t PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA{37};
inline constexpr uint32_t PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS{6};
inline constexpr uint32_t PAYMENT_AUDIT_SEAL_DELAY{240};
inline constexpr uint32_t PAYMENT_AUDIT_RECEIPT_DELAY{10};
inline constexpr std::size_t PAYMENT_AUDIT_SIGNATURE_COUNT{
    REQUIRED_QUORUMS * QUORUM_THRESHOLD};
inline constexpr std::size_t PAYMENT_AUDIT_REPORT_ONLINE_THRESHOLD{
    QUORUM_MAX_BYZANTINE + 1};
inline constexpr uint16_t PAYMENT_AUDIT_MAX_USES_PER_CHILD{ACTIVE_QUORUMS};
inline constexpr std::size_t MAX_PAYMENT_AUDIT_CERTIFICATE_SIZE{4'000'000};

inline constexpr std::string_view PAYMENT_AUDIT_SELECTION_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_SELECTION_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_COMMITMENT_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_COMMITMENT_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_DESCRIPTOR_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_DESCRIPTOR_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_SHARE_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_SHARE_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_SHARE_ID_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_SHARE_ID_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_LOGICAL_ID_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_LOGICAL_ID_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_WITNESS_ID_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_WITNESS_ID_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_RESULT_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_RESULT_V1"};
inline constexpr std::string_view PAYMENT_AUDIT_RECEIPT_STATE_DOMAIN{
    "SYS_PQ_PAYMENT_AUDIT_RECEIPT_STATE_V1"};

static_assert(PAYMENT_AUDIT_ROW_PERIOD == PQ_BTCC_CANDIDATE_PERIOD);
static_assert(PAYMENT_AUDIT_ROW_DEADLINE_DELAY % PQ_CL_PERIOD == 0);
static_assert(PAYMENT_AUDIT_SEAL_DELAY % PQ_CL_PERIOD == 0);
static_assert(PAYMENT_AUDIT_RECEIPT_DELAY == PQ_BTCC_CANDIDATE_PERIOD);
// A child epoch participates in at most one audit for each network epoch in
// which it is active. Audit uses are purpose-separated from ordinary CL uses.
static_assert(PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD +
                  PAYMENT_AUDIT_MAX_USES_PER_CHILD <=
              SCHEDULED_WOTS_USAGE_CAP);
static_assert(PAYMENT_AUDIT_MAX_USES_PER_CHILD ==
              SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_COUNT);
static_assert(PAYMENT_AUDIT_REPORT_ONLINE_THRESHOLD == 134);
static_assert(QUORUM_MIN_VALID == 300);
static_assert(PAYMENT_AUDIT_REPORT_ONLINE_THRESHOLD * 2 >
              QUORUM_THRESHOLD);

/** Periodic inventory reconciliation for the selected A response set. */
struct PaymentAuditHave {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) +
        sizeof(int32_t) +
        2 * 32 + BITMAP_SIZE};

    uint16_t version{PAYMENT_AUDIT_VERSION};
    uint32_t epoch{0};
    uint8_t row_index{0};
    int32_t response_height{-1};
    uint256 response_chainlock_logical_id;
    uint256 subject_descriptor_hash;
    QuorumBitmap available_members{};

    SERIALIZE_METHODS(PaymentAuditHave, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.row_index,
                  obj.response_height,
                  obj.response_chainlock_logical_id,
                  obj.subject_descriptor_hash, obj.available_members);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit HAVE");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditHave&,
                           const PaymentAuditHave&) = default;
};

static_assert(PaymentAuditHave::WIRE_SIZE == 125);

/** Exact normal A ChainLock share retained only until the B audit seals. */
struct PaymentAuditResponse {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t) + 32 +
        ChainLockShare::WIRE_SIZE};

    uint16_t version{PAYMENT_AUDIT_VERSION};
    uint32_t epoch{0};
    uint8_t row_index{0};
    uint256 subject_descriptor_hash;
    ChainLockShare response;

    SERIALIZE_METHODS(PaymentAuditResponse, obj)
    {
        READWRITE(obj.version, obj.epoch, obj.row_index,
                  obj.subject_descriptor_hash, obj.response);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit response");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditResponse&,
                           const PaymentAuditResponse&) = default;
};

static_assert(PaymentAuditResponse::WIRE_SIZE == 1'870);

struct PaymentAuditScheduleConfig {
    ChainLockScheduleConfig chainlock;
    BTCCScheduleConfig btcc;

    [[nodiscard]] bool IsValid() const noexcept;
    friend bool operator==(const PaymentAuditScheduleConfig&,
                           const PaymentAuditScheduleConfig&) = default;
};

struct PaymentAuditRowSchedule {
    int32_t response_height{-1};
    int32_t deadline_height{-1};

    friend bool operator==(const PaymentAuditRowSchedule&,
                           const PaymentAuditRowSchedule&) = default;
};

struct PaymentAuditCarrierWindow {
    uint32_t epoch{0};
    int32_t start_height{-1};
    int32_t end_height_exclusive{-1};

    [[nodiscard]] bool Contains(int32_t height) const noexcept;
    friend bool operator==(const PaymentAuditCarrierWindow&,
                           const PaymentAuditCarrierWindow&) = default;
};

/** Twenty-four frozen rows followed by one post-deadline ADVANCE anchor. */
struct PaymentAuditEpochSchedule {
    uint32_t epoch{0};
    std::array<PaymentAuditRowSchedule, PAYMENT_AUDIT_ROW_COUNT> rows{};
    int32_t anchor_height{-1};
    int32_t seal_height{-1};
    int32_t carrier_start_height{-1};
    int32_t carrier_end_height_exclusive{-1};

    [[nodiscard]] bool IsStructurallyValid(
        const PaymentAuditScheduleConfig& config) const noexcept;
    friend bool operator==(const PaymentAuditEpochSchedule&,
                           const PaymentAuditEpochSchedule&) = default;
};

[[nodiscard]] std::optional<PaymentAuditEpochSchedule>
BuildPaymentAuditEpochSchedule(const PaymentAuditScheduleConfig& config,
                               uint32_t epoch) noexcept;

/** Canonical one-time WOTS+ audit leaf for a child active at the seal. */
[[nodiscard]] std::optional<uint8_t> PaymentAuditLeafIndex(
    const PaymentAuditScheduleConfig& config,
    uint32_t subject_epoch,
    int32_t seal_height,
    uint32_t child_epoch) noexcept;

[[nodiscard]] std::optional<PaymentAuditCarrierWindow>
BuildPaymentAuditCarrierWindow(const PaymentAuditScheduleConfig& config,
                               uint32_t epoch) noexcept;

[[nodiscard]] bool IsPaymentAuditCarrierHeight(
    const PaymentAuditScheduleConfig& config, int32_t height) noexcept;

/** Return the epoch owning this canonical null-or-audit carrier slot. */
[[nodiscard]] std::optional<uint32_t> PaymentAuditReceiptSlotEpoch(
    const PaymentAuditScheduleConfig& config, int32_t height) noexcept;

struct PaymentAuditSeedPoint {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(int32_t) + 32 + BTCCursor::WIRE_SIZE + sizeof(uint8_t)};

    int32_t target_height{-1};
    uint256 chainlock_logical_id;
    BTCCursor accepted_cursor;
    BTCCAdvance advance{BTCCAdvance::ADVANCE};

    SERIALIZE_METHODS(PaymentAuditSeedPoint, obj)
    {
        uint8_t advance{static_cast<uint8_t>(obj.advance)};
        READWRITE(obj.target_height, obj.chainlock_logical_id,
                  obj.accepted_cursor, advance);
        SER_READ(obj, obj.advance = static_cast<BTCCAdvance>(advance));
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit seed point");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditSeedPoint&,
                           const PaymentAuditSeedPoint&) = default;
};

static_assert(PaymentAuditSeedPoint::WIRE_SIZE == 105);

/** Convert the exact non-null K+10 BTCC receipt into the audit seed point. */
[[nodiscard]] std::optional<PaymentAuditSeedPoint>
PaymentAuditSeedPointFromBTCCReceipt(const BTCCReceipt& receipt) noexcept;

/** Reconstruct the exact BTCC receipt bytes committed by one seed point. */
[[nodiscard]] std::optional<BTCCReceipt>
BTCCReceiptFromPaymentAuditSeedPoint(
    const PaymentAuditSeedPoint& seed_point) noexcept;

struct PaymentAuditSeed {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint32_t) + PaymentAuditSeedPoint::WIRE_SIZE +
        2 * sizeof(int32_t) + 32};

    uint32_t epoch{0};
    PaymentAuditSeedPoint anchor;
    int32_t anchor_btc_height{-1};
    int32_t future_btc_height{-1};
    uint256 future_btc_hash;

    SERIALIZE_METHODS(PaymentAuditSeed, obj)
    {
        READWRITE(obj.epoch, obj.anchor, obj.anchor_btc_height,
                  obj.future_btc_height, obj.future_btc_hash);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical payment-audit seed");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditSeed&,
                           const PaymentAuditSeed&) = default;
};

static_assert(PaymentAuditSeed::WIRE_SIZE == 149);

struct PaymentAuditRound {
    PaymentAuditSeed seed;
    uint8_t selected_row{0};
    int32_t response_height{-1};
    int32_t deadline_height{-1};
    int32_t seal_height{-1};
    int32_t carrier_start_height{-1};
    int32_t carrier_end_height_exclusive{-1};

    friend bool operator==(const PaymentAuditRound&,
                           const PaymentAuditRound&) = default;
};

[[nodiscard]] uint256 GetPaymentAuditSelectionHash(
    const uint256& genesis_hash,
    const uint256& subject_descriptor_hash,
    const PaymentAuditSeed& seed);

[[nodiscard]] std::optional<PaymentAuditRound> SelectPaymentAuditRound(
    const PaymentAuditScheduleConfig& config,
    const PaymentAuditEpochSchedule& schedule,
    const uint256& genesis_hash,
    const uint256& subject_descriptor_hash,
    const PaymentAuditSeed& seed) noexcept;

/** Common base bound to ordinary ChainLocked B. Each signer separately binds
 * its own frozen-row observation report below. */
struct PaymentAuditCommitment {
    static constexpr std::size_t WIRE_SIZE{
        2 * sizeof(uint16_t) + PaymentAuditSeed::WIRE_SIZE +
        sizeof(uint8_t) + 3 * sizeof(int32_t) + 32 + sizeof(uint8_t) +
        sizeof(uint32_t) + 2 * 32 + BITMAP_SIZE + 32};

    uint16_t version{PAYMENT_AUDIT_VERSION};
    uint16_t child_profile{CHILD_SCHEDULED_WOTS_SHAKE_128_V1};
    PaymentAuditSeed seed;
    uint8_t selected_row{0};
    int32_t response_height{-1};
    int32_t deadline_height{-1};
    uint256 response_chainlock_logical_id;
    BTCCAdvance response_advance{BTCCAdvance::ADVANCE};
    int32_t seal_height{-1};
    uint32_t subject_epoch{0};
    uint256 subject_quorum_base_hash;
    uint256 subject_descriptor_hash;
    QuorumBitmap subject_valid_members{};
    uint256 previous_probation_state_hash;

    SERIALIZE_METHODS(PaymentAuditCommitment, obj)
    {
        uint8_t response_advance{static_cast<uint8_t>(obj.response_advance)};
        READWRITE(obj.version, obj.child_profile, obj.seed,
                  obj.selected_row, obj.response_height,
                  obj.deadline_height,
                  obj.response_chainlock_logical_id, response_advance,
                  obj.seal_height, obj.subject_epoch,
                  obj.subject_quorum_base_hash,
                  obj.subject_descriptor_hash, obj.subject_valid_members,
                  obj.previous_probation_state_hash);
        SER_READ(obj, obj.response_advance =
                          static_cast<BTCCAdvance>(response_advance));
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit commitment");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditCommitment&,
                           const PaymentAuditCommitment&) = default;
};

static_assert(PaymentAuditCommitment::WIRE_SIZE == 349);

struct PaymentAuditStatement {
    static constexpr std::size_t WIRE_SIZE{
        PaymentAuditCommitment::WIRE_SIZE +
        ChainLockStatement::WIRE_SIZE};

    PaymentAuditCommitment commitment;
    // The compact ordinary-B statement makes an archived audit certificate
    // independently verifiable without retaining B's second full witness.
    // Live signers still require that exact ordinary ChainLock before signing.
    ChainLockStatement seal_statement;

    SERIALIZE_METHODS(PaymentAuditStatement, obj)
    {
        READWRITE(obj.commitment, obj.seal_statement);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit statement");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditStatement&,
                           const PaymentAuditStatement&) = default;
};

static_assert(PaymentAuditStatement::WIRE_SIZE == 862);

struct PaymentAuditShareTranscript {
    static constexpr std::size_t WIRE_SIZE{
        PaymentAuditStatement::WIRE_SIZE + BITMAP_SIZE +
        sizeof(uint32_t) + 32 + sizeof(uint16_t) + 32};

    PaymentAuditStatement statement;
    QuorumBitmap reporter_observed_members{};
    uint32_t quorum_epoch{0};
    uint256 quorum_base_hash;
    uint16_t member_index{std::numeric_limits<uint16_t>::max()};
    uint256 member_pro_tx_hash;

    SERIALIZE_METHODS(PaymentAuditShareTranscript, obj)
    {
        READWRITE(obj.statement, obj.reporter_observed_members,
                  obj.quorum_epoch, obj.quorum_base_hash, obj.member_index,
                  obj.member_pro_tx_hash);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit share transcript");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditShareTranscript&,
                           const PaymentAuditShareTranscript&) = default;
};

static_assert(PaymentAuditShareTranscript::WIRE_SIZE == 982);

struct PaymentAuditShare {
    static constexpr std::size_t WIRE_SIZE{
        PaymentAuditShareTranscript::WIRE_SIZE +
        AuthenticatedChildSignature::WIRE_SIZE};

    PaymentAuditShareTranscript transcript;
    AuthenticatedChildSignature authenticated_signature;

    SERIALIZE_METHODS(PaymentAuditShare, obj)
    {
        READWRITE(obj.transcript, obj.authenticated_signature);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit share");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] uint256 GetId(const uint256& genesis_hash) const;
    friend bool operator==(const PaymentAuditShare&,
                           const PaymentAuditShare&) = default;
};

static_assert(PaymentAuditShare::WIRE_SIZE == 2'230);

/** One signer-bound report, aligned with signer_bitmaps canonical order. */
struct PaymentAuditReportWitness {
    static constexpr std::size_t WIRE_SIZE{
        BITMAP_SIZE + AuthenticatedChildSignature::WIRE_SIZE};

    QuorumBitmap observed_members{};
    AuthenticatedChildSignature authenticated_signature;

    SERIALIZE_METHODS(PaymentAuditReportWitness, obj)
    {
        READWRITE(obj.observed_members, obj.authenticated_signature);
    }

    [[nodiscard]] bool IsStructurallyValid(
        const QuorumBitmap& subject_valid_members) const noexcept;
    friend bool operator==(const PaymentAuditReportWitness&,
                           const PaymentAuditReportWitness&) = default;
};

static_assert(PaymentAuditReportWitness::WIRE_SIZE == 1'298);

struct FinalPaymentAudit {
    static constexpr std::size_t WIRE_SIZE{
        PaymentAuditStatement::WIRE_SIZE + sizeof(uint8_t) +
        ACTIVE_QUORUMS * BITMAP_SIZE + sizeof(uint16_t) +
        PAYMENT_AUDIT_SIGNATURE_COUNT *
            PaymentAuditReportWitness::WIRE_SIZE};

    PaymentAuditStatement statement;
    uint8_t selected_quorum_mask{0};
    std::array<QuorumBitmap, ACTIVE_QUORUMS> signer_bitmaps{};
    std::vector<PaymentAuditReportWitness> report_witnesses;

    SERIALIZE_METHODS(FinalPaymentAudit, obj)
    {
        READWRITE(obj.statement, obj.selected_quorum_mask);
        SER_READ(obj, if (!obj.statement.IsStructurallyValid() ||
                          !IsSelectedQuorumMask(obj.selected_quorum_mask)) {
            throw std::ios_base::failure("invalid payment-audit header");
        });
        for (auto& bitmap : obj.signer_bitmaps) READWRITE(bitmap);
        uint16_t report_count{
            static_cast<uint16_t>(obj.report_witnesses.size())};
        SER_WRITE(obj, if (obj.report_witnesses.size() !=
                           PAYMENT_AUDIT_SIGNATURE_COUNT) {
            throw std::ios_base::failure(
                "invalid payment-audit report count");
        });
        READWRITE(report_count);
        SER_READ(obj, if (report_count != PAYMENT_AUDIT_SIGNATURE_COUNT) {
            throw std::ios_base::failure(
                "invalid payment-audit report count");
        });
        SER_READ(obj, obj.report_witnesses.resize(
                          PAYMENT_AUDIT_SIGNATURE_COUNT));
        for (auto& witness : obj.report_witnesses) READWRITE(witness);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical final payment audit");
        });
    }

    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    [[nodiscard]] uint256 GetLogicalId(const uint256& genesis_hash) const;
    [[nodiscard]] uint256 GetWitnessId(const uint256& genesis_hash) const;
    [[nodiscard]] std::optional<std::size_t> SignatureOffset(
        uint8_t quorum_slot, uint16_t member_index) const noexcept;
    friend bool operator==(const FinalPaymentAudit&,
                           const FinalPaymentAudit&) = default;
};

static_assert(FinalPaymentAudit::WIRE_SIZE == 1'040'763);
static_assert(FinalPaymentAudit::WIRE_SIZE <
              MAX_PAYMENT_AUDIT_CERTIFICATE_SIZE);

/** Compact on-chain dependency. Null is an explicit fail-open/no-op. */
struct PaymentAuditReceipt {
    static constexpr std::size_t WIRE_SIZE{
        sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint32_t) +
        2 * sizeof(int32_t) + 6 * 32 + BITMAP_SIZE};

    uint16_t version{PAYMENT_AUDIT_RECEIPT_VERSION};
    uint8_t has_audit{0};
    uint32_t epoch{0};
    int32_t seal_height{-1};
    uint256 seal_block_hash;
    int32_t carrier_height{-1};
    uint256 audit_logical_id;
    uint256 audit_witness_id;
    uint256 commitment_hash;
    uint256 result_hash;
    uint256 next_probation_state_hash;
    QuorumBitmap online_members{};

    SERIALIZE_METHODS(PaymentAuditReceipt, obj)
    {
        READWRITE(obj.version, obj.has_audit, obj.epoch, obj.seal_height,
                  obj.seal_block_hash, obj.carrier_height,
                  obj.audit_logical_id, obj.audit_witness_id,
                  obj.commitment_hash, obj.result_hash,
                  obj.next_probation_state_hash, obj.online_members);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure(
                "non-canonical payment-audit receipt");
        });
    }

    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool IsStructurallyValid() const noexcept;
    friend bool operator==(const PaymentAuditReceipt&,
                           const PaymentAuditReceipt&) = default;
};

static_assert(PaymentAuditReceipt::WIRE_SIZE == 257);

/** Deterministic classification derived only from the exact 801 reports. */
struct PaymentAuditClassification {
    std::array<QuorumBitmap, ACTIVE_QUORUMS> online_by_reporter_roster{};
    QuorumBitmap online_members{};
    QuorumBitmap missed_members{};
    uint16_t online_count{0};
    bool conclusive{false};

    friend bool operator==(const PaymentAuditClassification&,
                           const PaymentAuditClassification&) = default;
};

/** Exact common statement compatibility for same-epoch live collection. */
[[nodiscard]] bool IsPaymentAuditCandidateCompatible(
    const FinalPaymentAudit& candidate,
    const PaymentAuditStatement& active_statement) noexcept;

[[nodiscard]] uint256 GetPaymentAuditCommitmentHash(
    const uint256& genesis_hash,
    const PaymentAuditCommitment& commitment);
[[nodiscard]] uint256 GetPaymentAuditDescriptorHash(
    const uint256& genesis_hash,
    const QuorumDescriptor& descriptor);

[[nodiscard]] std::optional<PaymentAuditClassification>
ClassifyPaymentAuditReports(const FinalPaymentAudit& audit) noexcept;
[[nodiscard]] uint256 GetPaymentAuditResultHash(
    const uint256& genesis_hash,
    const FinalPaymentAudit& audit,
    const PaymentAuditClassification& classification);
[[nodiscard]] uint256 GetPaymentAuditShareHash(
    const uint256& genesis_hash,
    const PaymentAuditShareTranscript& transcript);
[[nodiscard]] uint256 GetPaymentAuditShareId(
    const uint256& genesis_hash,
    const PaymentAuditShare& share);
[[nodiscard]] uint256 GetPaymentAuditLogicalId(
    const uint256& genesis_hash,
    const PaymentAuditStatement& statement);
[[nodiscard]] uint256 GetPaymentAuditWitnessId(
    const uint256& genesis_hash,
    const FinalPaymentAudit& audit);

[[nodiscard]] std::optional<PaymentAuditReceiptState>
ApplyPaymentAuditReceipt(
    const uint256& genesis_hash,
    const PaymentAuditReceiptState& previous,
    const PaymentAuditReceipt& receipt) noexcept;

} // namespace llmq::pq

/** Bounded, ambiguity-rejecting payment-audit coinbase-tail extraction. */
[[nodiscard]] bool ExtractPaymentAuditReceipt(
    const CBlock& block, llmq::pq::PaymentAuditReceipt& receipt);
[[nodiscard]] bool HasPaymentAuditReceiptCommitment(const CBlock& block);

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_H
