// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_collector.h>

#include <memusage.h>

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

ShareCollectionError MapReservedVerificationError(
    PaymentAuditVerificationError error)
{
    switch (error) {
    case PaymentAuditVerificationError::INVALID_CHILD_PROOF:
        return ShareCollectionError::INVALID_CHILD_PROOF;
    case PaymentAuditVerificationError::INVALID_PUBLIC_KEY:
        return ShareCollectionError::INVALID_PUBLIC_KEY;
    case PaymentAuditVerificationError::INVALID_SIGNATURE:
        return ShareCollectionError::INVALID_SIGNATURE;
    case PaymentAuditVerificationError::NONE:
        return ShareCollectionError::LOCAL_ERROR;
    default:
        return ShareCollectionError::LOCAL_ERROR;
    }
}

void ClearBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] &=
        static_cast<uint8_t>(~(uint8_t{1} << (member % 8)));
}

} // namespace

CollectedPaymentAuditFinalization::CollectedPaymentAuditFinalization(
    FinalPaymentAudit certificate,
    PreparedPaymentAuditContextPtr context)
    : m_certificate{std::move(certificate)},
      m_context{std::move(context)}
{
}

PaymentAuditCollector::ShareVerificationReservation::
    ShareVerificationReservation(
        PreparedPaymentAuditContextPtr context,
        std::shared_ptr<const uint8_t> collector_token,
        PaymentAuditShare share,
        std::size_t quorum_slot,
        uint16_t member_index)
    : m_context{std::move(context)},
      m_collector_token{std::move(collector_token)},
      m_share{std::move(share)},
      m_quorum_slot{quorum_slot},
      m_member_index{member_index}
{
}

PaymentAuditCollector::PaymentAuditCollector(
    PreparedPaymentAuditContextPtr context)
    : m_context{std::move(context)},
      m_instance_token{std::make_shared<uint8_t>(0)}
{
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

std::optional<PaymentAuditCollector::ShareVerificationReservation>
PaymentAuditCollector::ReserveShareVerification(
    const PaymentAuditShare& share,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ShareCollectionError::INVALID_SHARE);
        return std::nullopt;
    }
    if (share.transcript.statement != m_context->Statement()) {
        SetError(error, ShareCollectionError::STATEMENT_MISMATCH);
        return std::nullopt;
    }
    const auto slot{m_context->FindQuorumSlot(share.transcript)};
    if (!slot) {
        SetError(error, ShareCollectionError::UNKNOWN_QUORUM);
        return std::nullopt;
    }
    if ((m_context->AuthorizationMask() & (uint8_t{1} << *slot)) == 0) {
        SetError(error, ShareCollectionError::INVALID_CONTEXT);
        return std::nullopt;
    }
    const uint16_t member_index{share.transcript.member_index};
    if (member_index >= QUORUM_SIZE) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return std::nullopt;
    }
    const auto& roster{m_context->Rosters()[*slot]};
    const auto& member{roster.members[member_index]};
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID ||
        !IsBitSet(roster.descriptor.valid_members, member_index) ||
        !member.eligible || !member.child_root ||
        member.pro_tx_hash != share.transcript.member_pro_tx_hash) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return std::nullopt;
    }
    auto& quorum_shares{m_shares[*slot]};
    if (quorum_shares.contains(member_index) ||
        IsBitSet(m_pending_shares[*slot], member_index)) {
        SetError(error, ShareCollectionError::DUPLICATE);
        return std::nullopt;
    }

    SetBit(m_pending_shares[*slot], member_index);
    return ShareVerificationReservation{
        m_context, m_instance_token, share, *slot, member_index};
}

void PaymentAuditCollector::VerifyReservedShare(
    ShareVerificationReservation& reservation)
{
    if (reservation.m_verification_state !=
        ShareVerificationReservation::VerificationState::PENDING) {
        return;
    }
    if (!reservation.m_context || !reservation.m_collector_token) {
        reservation.m_verification_state =
            ShareVerificationReservation::VerificationState::INVALID;
        reservation.m_verification_error = ShareCollectionError::LOCAL_ERROR;
        return;
    }
    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::NONE};
    auto check{PreparePaymentAuditShareVerification(
        reservation.m_share, *reservation.m_context, &verification_error)};
    if (!check) {
        reservation.m_verification_state =
            ShareVerificationReservation::VerificationState::INVALID;
        reservation.m_verification_error =
            MapReservedVerificationError(verification_error);
        return;
    }
    if (!(*check)()) {
        reservation.m_verification_state =
            ShareVerificationReservation::VerificationState::INVALID;
        reservation.m_verification_error =
            ShareCollectionError::INVALID_SIGNATURE;
        return;
    }

    reservation.m_verification_state =
        ShareVerificationReservation::VerificationState::VALID;
    reservation.m_verification_error = ShareCollectionError::NONE;
}

ShareCollectionResult PaymentAuditCollector::CompleteShareVerification(
    ShareVerificationReservation reservation,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!reservation.m_context || !reservation.m_collector_token ||
        reservation.m_context != m_context ||
        reservation.m_collector_token != m_instance_token ||
        reservation.m_quorum_slot >= ACTIVE_QUORUMS ||
        reservation.m_member_index >= QUORUM_SIZE) {
        SetError(error, ShareCollectionError::LOCAL_ERROR);
        return ShareCollectionResult::REJECTED;
    }

    auto& pending{m_pending_shares[reservation.m_quorum_slot]};
    if (!IsBitSet(pending, reservation.m_member_index)) {
        SetError(error, ShareCollectionError::LOCAL_ERROR);
        return ShareCollectionResult::REJECTED;
    }
    ClearBit(pending, reservation.m_member_index);

    if (reservation.m_verification_state !=
        ShareVerificationReservation::VerificationState::VALID) {
        const ShareCollectionError verification_error{
            reservation.m_verification_state ==
                    ShareVerificationReservation::VerificationState::INVALID
                ? reservation.m_verification_error
                : ShareCollectionError::LOCAL_ERROR};
        SetError(error, verification_error);
        return ShareCollectionResult::REJECTED;
    }

    auto& quorum_shares{m_shares[reservation.m_quorum_slot]};
    if (quorum_shares.contains(reservation.m_member_index)) {
        SetError(error, ShareCollectionError::DUPLICATE);
        return ShareCollectionResult::DUPLICATE;
    }
    quorum_shares.emplace(
        reservation.m_member_index,
        PaymentAuditReportWitness{
            reservation.m_share.transcript.reporter_observed_members,
            std::move(reservation.m_share.authenticated_signature)});
    return ShareCollectionResult::ACCEPTED;
}

ShareCollectionResult PaymentAuditCollector::AddVerifiedShare(
    const PaymentAuditShare& share,
    ShareCollectionError* error)
{
    ShareCollectionError reservation_error{ShareCollectionError::NONE};
    auto reservation{ReserveShareVerification(share, &reservation_error)};
    if (!reservation) {
        SetError(error, reservation_error);
        return reservation_error == ShareCollectionError::DUPLICATE
            ? ShareCollectionResult::DUPLICATE
            : ShareCollectionResult::REJECTED;
    }
    VerifyReservedShare(*reservation);
    return CompleteShareVerification(std::move(*reservation), error);
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

bool PaymentAuditCollector::HasAcceptedShare(
    const PaymentAuditShareTranscript& transcript) const noexcept
{
    const auto slot{m_context->FindQuorumSlot(transcript)};
    return slot && transcript.member_index < QUORUM_SIZE &&
           m_shares[*slot].contains(transcript.member_index);
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

std::size_t PaymentAuditCollector::MemoryUsage() const noexcept
{
    std::size_t usage{sizeof(PaymentAuditCollector)};
    for (const auto& shares : m_shares) {
        usage += memusage::DynamicUsage(shares);
    }
    return usage;
}

CollectedPaymentAuditFinalizationPtr
PaymentAuditCollector::FinalizeCollection() const
{
    auto certificate{BuildFinalCertificate()};
    if (!certificate || !m_context ||
        certificate->statement != m_context->Statement()) {
        return nullptr;
    }
    return CollectedPaymentAuditFinalizationPtr{
        new CollectedPaymentAuditFinalization{
            std::move(*certificate), m_context}};
}

std::optional<FinalPaymentAudit>
PaymentAuditCollector::BuildFinalCertificate() const
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
