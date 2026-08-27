// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_collector.h>

#include <algorithm>
#include <utility>

namespace llmq::pq {
namespace {

void SetError(ShareCollectionError* error, ShareCollectionError value)
{
    if (error != nullptr) *error = value;
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member)
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

ShareCollectionError MapVerificationError(
    PaymentAuditVerificationError error)
{
    switch (error) {
    case PaymentAuditVerificationError::INVALID_SIGNATURE:
        return ShareCollectionError::INVALID_SIGNATURE;
    case PaymentAuditVerificationError::INVALID_PUBLIC_KEY:
        return ShareCollectionError::INVALID_PUBLIC_KEY;
    case PaymentAuditVerificationError::INVALID_SIGNER:
        return ShareCollectionError::INVALID_MEMBER;
    case PaymentAuditVerificationError::NONE:
        return ShareCollectionError::NONE;
    default:
        return ShareCollectionError::INVALID_CONTEXT;
    }
}

} // namespace

PaymentAuditCollector::PaymentAuditCollector(
    PreparedPaymentAuditContextPtr context)
    : m_context{std::move(context)}
{
}

std::unique_ptr<PaymentAuditCollector> PaymentAuditCollector::Create(
    const uint256& genesis_hash,
    PaymentAuditScheduleConfig schedule,
    PaymentAuditStatement statement,
    const FinalChainLock& seal_chainlock,
    FrozenQuorumRostersPtr rosters,
    uint8_t authorization_mask,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (genesis_hash.IsNull() || !schedule.IsValid() ||
        !statement.IsStructurallyValid() || !rosters) {
        SetError(error, ShareCollectionError::INVALID_ARGUMENT);
        return nullptr;
    }
    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    auto context{PreparedPaymentAuditContext::Create(
        genesis_hash, schedule, std::move(statement), seal_chainlock,
        std::move(rosters), authorization_mask, &verification_error)};
    if (!context) {
        SetError(error, MapVerificationError(verification_error));
        return nullptr;
    }
    return Create(std::move(context), error);
}

std::unique_ptr<PaymentAuditCollector> PaymentAuditCollector::Create(
    PreparedPaymentAuditContextPtr context,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!context) {
        SetError(error, ShareCollectionError::INVALID_ARGUMENT);
        return nullptr;
    }
    return std::unique_ptr<PaymentAuditCollector>{
        new PaymentAuditCollector{std::move(context)}};
}

ShareCollectionResult PaymentAuditCollector::AddVerifiedShare(
    const PaymentAuditShare& share,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ShareCollectionError::INVALID_SHARE);
        return ShareCollectionResult::REJECTED;
    }
    if (share.transcript.statement != m_context->Statement()) {
        SetError(error, ShareCollectionError::STATEMENT_MISMATCH);
        return ShareCollectionResult::REJECTED;
    }
    const auto slot{m_context->FindQuorumSlot(share.transcript)};
    if (!slot) {
        SetError(error, ShareCollectionError::UNKNOWN_QUORUM);
        return ShareCollectionResult::REJECTED;
    }
    if ((m_context->AuthorizationMask() & (uint8_t{1} << *slot)) == 0) {
        SetError(error, ShareCollectionError::INVALID_CONTEXT);
        return ShareCollectionResult::REJECTED;
    }
    const uint16_t member_index{share.transcript.member_index};
    if (member_index >= QUORUM_SIZE) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return ShareCollectionResult::REJECTED;
    }
    const auto& roster{m_context->Rosters()[*slot]};
    const auto& member{roster.members[member_index]};
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID ||
        !IsBitSet(roster.descriptor.valid_members, member_index) ||
        !member.eligible || !member.child_root ||
        member.pro_tx_hash != share.transcript.member_pro_tx_hash) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return ShareCollectionResult::REJECTED;
    }
    auto& quorum_shares{m_shares[*slot]};
    if (quorum_shares.contains(member_index)) {
        SetError(error, ShareCollectionError::DUPLICATE);
        return ShareCollectionResult::DUPLICATE;
    }

    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    auto check{PreparePaymentAuditShareVerification(
        share, *m_context, &verification_error)};
    if (!check) {
        SetError(error, MapVerificationError(verification_error));
        return ShareCollectionResult::REJECTED;
    }
    if (!(*check)()) {
        SetError(error, ShareCollectionError::INVALID_SIGNATURE);
        return ShareCollectionResult::REJECTED;
    }
    quorum_shares.emplace(
        member_index,
        PaymentAuditReportWitness{
            share.transcript.reporter_observed_members,
            share.authenticated_signature});
    return ShareCollectionResult::ACCEPTED;
}

std::array<std::size_t, ACTIVE_QUORUMS>
PaymentAuditCollector::ShareCounts() const
{
    std::array<std::size_t, ACTIVE_QUORUMS> counts{};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        counts[slot] = m_shares[slot].size();
    }
    return counts;
}

bool PaymentAuditCollector::IsComplete() const
{
    std::size_t ready{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((m_context->AuthorizationMask() & (uint8_t{1} << slot)) != 0 &&
            m_shares[slot].size() >= QUORUM_THRESHOLD) {
            ++ready;
        }
    }
    return ready >= REQUIRED_QUORUMS;
}

std::optional<FinalPaymentAudit> PaymentAuditCollector::Finalize() const
{
    if (!IsComplete()) return std::nullopt;
    FinalPaymentAudit result;
    result.statement = m_context->Statement();
    result.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    std::size_t selected{0};
    for (std::size_t slot{0};
         slot < ACTIVE_QUORUMS && selected < REQUIRED_QUORUMS; ++slot) {
        if ((m_context->AuthorizationMask() &
             (uint8_t{1} << slot)) == 0) {
            continue;
        }
        if (m_shares[slot].size() < QUORUM_THRESHOLD) continue;
        result.selected_quorum_mask |=
            static_cast<uint8_t>(uint8_t{1} << slot);
        std::size_t added{0};
        for (const auto& [member_index, witness] : m_shares[slot]) {
            if (added == QUORUM_THRESHOLD) break;
            SetBit(result.signer_bitmaps[slot], member_index);
            result.report_witnesses.push_back(witness);
            ++added;
        }
        if (added != QUORUM_THRESHOLD) return std::nullopt;
        ++selected;
    }
    if (selected != REQUIRED_QUORUMS || !result.IsStructurallyValid()) {
        return std::nullopt;
    }
    return result;
}

} // namespace llmq::pq
