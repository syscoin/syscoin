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
    uint256 genesis_hash,
    PaymentAuditStatement statement,
    FinalChainLock seal_chainlock,
    FrozenQuorumRostersPtr rosters)
    : m_genesis_hash{std::move(genesis_hash)},
      m_statement{std::move(statement)},
      m_seal_chainlock{std::move(seal_chainlock)},
      m_rosters{std::move(rosters)}
{
}

std::unique_ptr<PaymentAuditCollector> PaymentAuditCollector::Create(
    const uint256& genesis_hash,
    PaymentAuditStatement statement,
    FinalChainLock seal_chainlock,
    FrozenQuorumRostersPtr rosters,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (genesis_hash.IsNull() || !statement.IsStructurallyValid() ||
        !rosters) {
        SetError(error, ShareCollectionError::INVALID_ARGUMENT);
        return nullptr;
    }
    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    if (!ValidatePaymentAuditLiveSeal(genesis_hash, statement,
                                      seal_chainlock,
                                      &verification_error) ||
        !ValidatePaymentAuditContext(genesis_hash, statement, *rosters,
                                     &verification_error)) {
        SetError(error, MapVerificationError(verification_error));
        return nullptr;
    }
    return std::unique_ptr<PaymentAuditCollector>{new PaymentAuditCollector{
        genesis_hash, std::move(statement), std::move(seal_chainlock),
        std::move(rosters)}};
}

std::optional<std::size_t> PaymentAuditCollector::FindQuorumSlot(
    const PaymentAuditShareTranscript& transcript) const
{
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& descriptor{(*m_rosters)[slot].descriptor};
        if (descriptor.epoch == transcript.quorum_epoch &&
            descriptor.base_hash == transcript.quorum_base_hash) {
            return slot;
        }
    }
    return std::nullopt;
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
    if (share.transcript.statement != m_statement) {
        SetError(error, ShareCollectionError::STATEMENT_MISMATCH);
        return ShareCollectionResult::REJECTED;
    }
    const auto slot{FindQuorumSlot(share.transcript)};
    if (!slot) {
        SetError(error, ShareCollectionError::UNKNOWN_QUORUM);
        return ShareCollectionResult::REJECTED;
    }
    const uint16_t member_index{share.transcript.member_index};
    if (member_index >= QUORUM_SIZE) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return ShareCollectionResult::REJECTED;
    }
    const auto& roster{(*m_rosters)[*slot]};
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
        m_genesis_hash, share, *m_rosters,
        &verification_error)};
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
    const auto ready{std::count_if(m_shares.begin(), m_shares.end(),
                                   [](const auto& shares) {
                                       return shares.size() >=
                                              QUORUM_THRESHOLD;
                                   })};
    return ready >= static_cast<decltype(ready)>(REQUIRED_QUORUMS);
}

std::optional<FinalPaymentAudit> PaymentAuditCollector::Finalize() const
{
    if (!IsComplete()) return std::nullopt;
    FinalPaymentAudit result;
    result.statement = m_statement;
    result.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    std::size_t selected{0};
    for (std::size_t slot{0};
         slot < ACTIVE_QUORUMS && selected < REQUIRED_QUORUMS; ++slot) {
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
