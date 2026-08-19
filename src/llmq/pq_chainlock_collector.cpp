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
        return ShareCollectionError::NONE;
    default:
        return ShareCollectionError::INVALID_CONTEXT;
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

} // namespace

ChainLockCollector::ChainLockCollector(
    uint256 genesis_hash,
    ChainLockStatement statement,
    FrozenQuorumRostersPtr rosters,
    uint8_t authorization_mask)
    : m_genesis_hash{std::move(genesis_hash)},
      m_statement{std::move(statement)},
      m_rosters{std::move(rosters)},
      m_authorization_mask{authorization_mask}
{
}

std::unique_ptr<ChainLockCollector> ChainLockCollector::Create(
    const uint256& genesis_hash,
    ChainLockStatement statement,
    FrozenQuorumRostersPtr rosters,
    uint8_t authorization_mask,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (genesis_hash.IsNull() || !statement.IsStructurallyValid() || !rosters) {
        SetError(error, ShareCollectionError::INVALID_ARGUMENT);
        return nullptr;
    }
    ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
    if (!ValidateFrozenQuorumContext(genesis_hash, statement, *rosters,
                                     authorization_mask,
                                     &verification_error)) {
        SetError(error, MapVerificationError(verification_error));
        return nullptr;
    }
    return std::unique_ptr<ChainLockCollector>{new ChainLockCollector{
        genesis_hash, std::move(statement), std::move(rosters),
        authorization_mask}};
}

std::optional<std::size_t> ChainLockCollector::FindQuorumSlot(
    const ChainLockShareTranscript& transcript) const
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

ShareCollectionResult ChainLockCollector::AddVerifiedShare(
    const ChainLockShare& share,
    ShareCollectionError* error)
{
    SetError(error, ShareCollectionError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, ShareCollectionError::INVALID_SHARE);
        return ShareCollectionResult::REJECTED;
    }
    if (share.GetStatement() != m_statement) {
        SetError(error, ShareCollectionError::STATEMENT_MISMATCH);
        return ShareCollectionResult::REJECTED;
    }
    const auto slot{FindQuorumSlot(share.transcript)};
    if (!slot) {
        SetError(error, ShareCollectionError::UNKNOWN_QUORUM);
        return ShareCollectionResult::REJECTED;
    }
    if ((m_authorization_mask & (uint8_t{1} << *slot)) == 0) {
        SetError(error, ShareCollectionError::INVALID_CONTEXT);
        return ShareCollectionResult::REJECTED;
    }
    const uint16_t member_index{share.transcript.member_index};
    if (member_index >= QUORUM_SIZE) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return ShareCollectionResult::REJECTED;
    }

    const auto& roster{(*m_rosters)[*slot]};
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID) {
        SetError(error, ShareCollectionError::INVALID_CONTEXT);
        return ShareCollectionResult::REJECTED;
    }
    const auto& member{roster.members[member_index]};
    if (!IsBitSet(roster.descriptor.valid_members, member_index) ||
        !member.eligible || !member.child_root ||
        member.pro_tx_hash != share.transcript.member_pro_tx_hash) {
        SetError(error, ShareCollectionError::INVALID_MEMBER);
        return ShareCollectionResult::REJECTED;
    }

    auto& quorum_shares{m_shares[*slot]};
    const auto existing{quorum_shares.find(member_index)};
    if (existing != quorum_shares.end()) {
        // A verified signer slot already contributes its only vote. Later
        // bytes cannot add weight and are not evidence against the transport
        // relay that delivered them, so discard them before verification.
        SetError(error, ShareCollectionError::DUPLICATE);
        return ShareCollectionResult::DUPLICATE;
    }

    ChainLockVerificationError verification_error{ChainLockVerificationError::NONE};
    auto check{PrepareChainLockShareVerification(
        m_genesis_hash, share, *m_rosters, m_authorization_mask,
        &verification_error)};
    if (!check) {
        SetError(error, MapVerificationError(verification_error));
        return ShareCollectionResult::REJECTED;
    }
    if (!(*check)()) {
        SetError(error, ShareCollectionError::INVALID_SIGNATURE);
        return ShareCollectionResult::REJECTED;
    }

    quorum_shares.emplace(member_index, share.authenticated_signature);
    return ShareCollectionResult::ACCEPTED;
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
        if ((m_authorization_mask & (uint8_t{1} << slot)) != 0 &&
            m_shares[slot].size() >= QUORUM_THRESHOLD) {
            ++ready;
        }
    }
    return ready >= REQUIRED_QUORUMS;
}

std::optional<FinalChainLock> ChainLockCollector::Finalize() const
{
    if (!IsComplete()) return std::nullopt;

    FinalChainLock result;
    result.statement = m_statement;
    result.signatures.reserve(FINAL_SIGNATURE_COUNT);

    std::size_t selected{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS && selected < REQUIRED_QUORUMS;
         ++slot) {
        if ((m_authorization_mask & (uint8_t{1} << slot)) == 0) continue;
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
