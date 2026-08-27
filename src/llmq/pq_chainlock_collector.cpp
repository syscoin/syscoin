// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>

#include <algorithm>
#include <utility>

namespace llmq::pq {
namespace {

void SetError(ShareCollectionError* error, ShareCollectionError value)
{
    if (error != nullptr) *error = value;
}

ShareCollectionError MapVerificationError(ChainLockVerificationError error)
{
    switch (error) {
    case ChainLockVerificationError::INVALID_PUBLIC_KEY:
        return ShareCollectionError::INVALID_PUBLIC_KEY;
    case ChainLockVerificationError::INVALID_SIGNATURE:
        return ShareCollectionError::INVALID_SIGNATURE;
    case ChainLockVerificationError::INVALID_SIGNER:
        return ShareCollectionError::INVALID_MEMBER;
    case ChainLockVerificationError::NONE:
        return ShareCollectionError::LOCAL_ERROR;
    default:
        return ShareCollectionError::INVALID_CONTEXT;
    }
}

ShareCollectionError MapReservedVerificationError(
    ChainLockVerificationError error)
{
    switch (error) {
    case ChainLockVerificationError::INVALID_CHILD_PROOF:
        return ShareCollectionError::INVALID_CHILD_PROOF;
    case ChainLockVerificationError::INVALID_PUBLIC_KEY:
        return ShareCollectionError::INVALID_PUBLIC_KEY;
    case ChainLockVerificationError::INVALID_SIGNATURE:
        return ShareCollectionError::INVALID_SIGNATURE;
    case ChainLockVerificationError::NONE:
        return ShareCollectionError::LOCAL_ERROR;
    default:
        return ShareCollectionError::LOCAL_ERROR;
    }
}

void SetBit(QuorumBitmap& bitmap, uint16_t member_index)
{
    bitmap[member_index / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member_index % 8));
}

bool IsBitSet(const QuorumBitmap& bitmap, uint16_t member_index)
{
    return (bitmap[member_index / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member_index % 8))) != 0;
}

void ClearBit(QuorumBitmap& bitmap, uint16_t member_index)
{
    bitmap[member_index / 8] &=
        static_cast<uint8_t>(~(uint8_t{1} << (member_index % 8)));
}

} // namespace

CollectedChainLockFinalization::CollectedChainLockFinalization(
    FinalChainLock certificate,
    PreparedChainLockContextPtr context)
    : m_certificate{std::move(certificate)},
      m_context{std::move(context)}
{
}

ChainLockCollector::ShareVerificationReservation::
    ShareVerificationReservation(
        PreparedChainLockContextPtr context,
        std::shared_ptr<const uint8_t> collector_token,
        ChainLockShare share,
        std::size_t quorum_slot,
        uint16_t member_index)
    : m_context{std::move(context)},
      m_collector_token{std::move(collector_token)},
      m_share{std::move(share)},
      m_quorum_slot{quorum_slot},
      m_member_index{member_index}
{
}

ChainLockCollector::ChainLockCollector(
    PreparedChainLockContextPtr context)
    : m_context{std::move(context)},
      m_instance_token{std::make_shared<uint8_t>(0)}
{
}

std::unique_ptr<ChainLockCollector> ChainLockCollector::Create(
    const uint256& genesis_hash,
    ChainLockScheduleConfig schedule,
    ChainLockStatement statement,
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
    ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
    auto context{PreparedChainLockContext::Create(
        genesis_hash, schedule, std::move(statement), std::move(rosters),
        authorization_mask, &verification_error)};
    if (!context) {
        SetError(error, MapVerificationError(verification_error));
        return nullptr;
    }
    return Create(std::move(context), error);
}

std::unique_ptr<ChainLockCollector> ChainLockCollector::Create(
    PreparedChainLockContextPtr context,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!context) {
        SetError(error, ShareCollectionError::INVALID_ARGUMENT);
        return nullptr;
    }
    return std::unique_ptr<ChainLockCollector>{
        new ChainLockCollector{std::move(context)}};
}

std::optional<ChainLockCollector::ShareVerificationReservation>
ChainLockCollector::ReserveShareVerification(
    const ChainLockShare& share,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ShareCollectionError::INVALID_SHARE);
        return std::nullopt;
    }
    if (share.GetStatement() != m_context->Statement()) {
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
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID) {
        SetError(error, ShareCollectionError::INVALID_CONTEXT);
        return std::nullopt;
    }
    const auto& member{roster.members[member_index]};
    if (!IsBitSet(roster.descriptor.valid_members, member_index) ||
        !member.eligible || !member.child_root ||
        member.pro_tx_hash != share.transcript.member_pro_tx_hash) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return std::nullopt;
    }

    auto& quorum_shares{m_shares[*slot]};
    if (quorum_shares.contains(member_index) ||
        IsBitSet(m_pending_shares[*slot], member_index)) {
        // An accepted or in-flight signer slot can contribute only one vote.
        // Later bytes cannot add weight and are not evidence against the
        // transport relay that delivered them, so skip their crypto work.
        SetError(error, ShareCollectionError::DUPLICATE);
        return std::nullopt;
    }

    SetBit(m_pending_shares[*slot], member_index);
    return ShareVerificationReservation{
        m_context, m_instance_token, share, *slot, member_index};
}

void ChainLockCollector::VerifyReservedShare(
    ShareVerificationReservation& reservation)
{
    if (reservation.m_verification_state !=
        ShareVerificationReservation::VerificationState::PENDING) {
        return;
    }
    if (!reservation.m_context || !reservation.m_collector_token) {
        reservation.m_verification_state =
            ShareVerificationReservation::VerificationState::INVALID;
        reservation.m_verification_error =
            ShareCollectionError::LOCAL_ERROR;
        return;
    }
    ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
    auto check{PrepareChainLockShareVerification(
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

ShareCollectionResult ChainLockCollector::CompleteShareVerification(
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
        std::move(reservation.m_share.authenticated_signature));
    return ShareCollectionResult::ACCEPTED;
}

ShareCollectionResult ChainLockCollector::AddVerifiedShare(
    const ChainLockShare& share,
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

std::array<std::size_t, ACTIVE_QUORUMS> ChainLockCollector::ShareCounts() const
{
    std::array<std::size_t, ACTIVE_QUORUMS> counts{};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        counts[slot] = m_shares[slot].size();
    }
    return counts;
}

bool ChainLockCollector::IsComplete() const
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

CollectedChainLockFinalizationPtr
ChainLockCollector::FinalizeCollection() const
{
    auto certificate{BuildFinalCertificate()};
    if (!certificate || !m_context ||
        certificate->statement != m_context->Statement()) {
        return nullptr;
    }
    return CollectedChainLockFinalizationPtr{
        new CollectedChainLockFinalization{
            std::move(*certificate), m_context}};
}

std::optional<FinalChainLock>
ChainLockCollector::BuildFinalCertificate() const
{
    if (!IsComplete()) return std::nullopt;

    FinalChainLock result;
    result.statement = m_context->Statement();
    result.signatures.reserve(FINAL_SIGNATURE_COUNT);

    std::size_t selected{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS && selected < REQUIRED_QUORUMS;
         ++slot) {
        if ((m_context->AuthorizationMask() &
             (uint8_t{1} << slot)) == 0) {
            continue;
        }
        if (m_shares[slot].size() < QUORUM_THRESHOLD) continue;
        result.selected_quorum_mask |= static_cast<uint8_t>(uint8_t{1} << slot);
        std::size_t added{0};
        for (const auto& [member_index, signature] : m_shares[slot]) {
            if (added == QUORUM_THRESHOLD) break;
            SetBit(result.signer_bitmaps[slot], member_index);
            result.signatures.push_back(signature);
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
