// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_signer.h>

#include <hash.h>

#include <algorithm>
#include <utility>

namespace llmq::pq {
namespace {

void SetError(ChainLockSigningError* error, ChainLockSigningError value)
{
    if (error != nullptr) *error = value;
}

ChainLockSigningError MapJournalError(PQSignerJournalOutcome outcome)
{
    switch (outcome) {
    case PQSignerJournalOutcome::CONFLICT:
    case PQSignerJournalOutcome::BRANCH_CONFLICT:
        return ChainLockSigningError::JOURNAL_CONFLICT;
    case PQSignerJournalOutcome::CONSUMED:
        return ChainLockSigningError::JOURNAL_CONSUMED;
    case PQSignerJournalOutcome::INVALID_ARGUMENT:
        return ChainLockSigningError::INVALID_ARGUMENT;
    default:
        return ChainLockSigningError::JOURNAL_FAILURE;
    }
}

PaymentAuditSigningResult Failure(ChainLockSigningError* error,
                                  ChainLockSigningError value)
{
    SetError(error, value);
    return {};
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member)
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

} // namespace

PaymentAuditShareSigner::PaymentAuditShareSigner(
    uint256 genesis_hash,
    uint256 local_pro_tx_hash,
    PaymentAuditScheduleConfig schedule,
    CPQSignerJournal& journal)
    : m_genesis_hash{std::move(genesis_hash)},
      m_local_pro_tx_hash{std::move(local_pro_tx_hash)},
      m_schedule{schedule},
      m_journal{journal}
{
}

PaymentAuditSigningResult PaymentAuditShareSigner::Sign(
    const PaymentAuditStatement& statement,
    const QuorumBitmap& reporter_observed_members,
    const FinalChainLock& seal_chainlock,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    uint8_t quorum_slot,
    uint16_t member_index,
    const scheduled_wots::SecretKey& child_secret_key,
    const ChildKeyProof& child_key_proof,
    const std::optional<PQSignerBranchLock>& expected_branch_lock,
    ChainLockSigningError* error)
{
    SetError(error, ChainLockSigningError::NONE);
    if (m_genesis_hash.IsNull() || m_local_pro_tx_hash.IsNull() ||
        !statement.IsStructurallyValid() ||
        !child_secret_key.IsValid()) {
        return Failure(error, ChainLockSigningError::INVALID_ARGUMENT);
    }
    if (!m_schedule.IsValid()) {
        return Failure(error, ChainLockSigningError::INVALID_SCHEDULE);
    }
    if (!IsEligibleChainLockTarget(m_schedule.chainlock,
                                   statement.commitment.seal_height)) {
        return Failure(error, ChainLockSigningError::INELIGIBLE_HEIGHT);
    }
    const auto expected_seal{NextEligibleChainLockTargetHeight(
        m_schedule.chainlock,
        statement.seal_statement.previous_chainlock_height)};
    if (!expected_seal || statement.commitment.seal_height !=
                              *expected_seal) {
        return Failure(error, ChainLockSigningError::INELIGIBLE_HEIGHT);
    }
    if (quorum_slot >= ACTIVE_QUORUMS) {
        return Failure(error, ChainLockSigningError::INVALID_QUORUM_SLOT);
    }
    if ((authorization_mask & (uint8_t{1} << quorum_slot)) == 0) {
        return Failure(error, ChainLockSigningError::INACTIVE_QUORUM);
    }
    PaymentAuditVerificationError context_error{
        PaymentAuditVerificationError::NONE};
    if (!ValidatePaymentAuditLiveSeal(m_genesis_hash, statement,
                                      seal_chainlock, &context_error) ||
        !ValidatePaymentAuditContext(m_genesis_hash, m_schedule, statement,
                                     rosters, authorization_mask,
                                     &context_error)) {
        return Failure(error, ChainLockSigningError::INVALID_CONTEXT);
    }
    const auto& roster{rosters[quorum_slot]};
    const auto leaf_index{PaymentAuditLeafIndex(
        m_schedule, statement.commitment.subject_epoch,
        statement.commitment.seal_height, roster.descriptor.epoch)};
    if (!IsEpochActiveForTarget(m_schedule.chainlock, roster.descriptor.epoch,
                                statement.commitment.seal_height) ||
        roster.descriptor.valid_count < QUORUM_MIN_VALID || !leaf_index) {
        return Failure(error, ChainLockSigningError::INACTIVE_QUORUM);
    }
    if (member_index >= QUORUM_SIZE ||
        !IsBitSet(roster.descriptor.valid_members, member_index)) {
        return Failure(error, ChainLockSigningError::INVALID_MEMBER);
    }
    const auto& member{roster.members[member_index]};
    if (member.pro_tx_hash != m_local_pro_tx_hash) {
        return Failure(error, ChainLockSigningError::WRONG_OPERATOR);
    }
    if (!member.eligible || !member.child_root) {
        return Failure(error, ChainLockSigningError::INVALID_MEMBER);
    }
    ChildPublicKey derived_public_key{};
    if (!child_secret_key.GetPublicKey(derived_public_key) ||
        !VerifyCommittedChildKeyProof(
            m_genesis_hash, member.child_root->commitment,
            roster.descriptor.epoch, child_key_proof) ||
        derived_public_key != child_key_proof.public_key) {
        return Failure(error, ChainLockSigningError::SECRET_KEY_MISMATCH);
    }

    PaymentAuditShare share;
    share.transcript = BuildPaymentAuditShareTranscript(
        statement, reporter_observed_members, roster.descriptor,
        member_index, member.pro_tx_hash);
    share.authenticated_signature.key_proof = child_key_proof;
    const uint256 message_hash{
        GetPaymentAuditShareHash(m_genesis_hash, share.transcript)};
    const PQSignerJournalKey journal_key{
        .genesis_hash = m_genesis_hash,
        .child_profile = statement.commitment.child_profile,
        .pro_tx_hash = m_local_pro_tx_hash,
        .quorum_epoch = roster.descriptor.epoch,
        .child_key_hash = ::Hash(child_key_proof.public_key),
        .leaf_index = *leaf_index,
        .purpose = PQSignerPurpose::PAYMENT_AUDIT,
        .absolute_height = statement.commitment.seal_height,
    };
    const PQSignerBranchLock seal_lock{
        seal_chainlock.statement.height,
        seal_chainlock.statement.block_hash,
        seal_chainlock.GetLogicalId(m_genesis_hash)};
    if (!expected_branch_lock || *expected_branch_lock != seal_lock) {
        return Failure(error, ChainLockSigningError::JOURNAL_CONFLICT);
    }
    const PQSignerJournalResult reservation{m_journal.Reserve(
        journal_key, message_hash, seal_lock, expected_branch_lock)};
    if (reservation.outcome == PQSignerJournalOutcome::REPLAY) {
        if (!reservation.signature) {
            return Failure(error, ChainLockSigningError::JOURNAL_FAILURE);
        }
        std::copy(reservation.signature->begin(),
                  reservation.signature->end(),
                  share.authenticated_signature.signature.begin());
        return {.share = std::move(share), .replayed = true};
    }
    if (reservation.outcome != PQSignerJournalOutcome::RESERVED) {
        return Failure(error, MapJournalError(reservation.outcome));
    }

    scheduled_wots::Message message;
    std::copy(message_hash.begin(), message_hash.end(), message.begin());
    if (!scheduled_wots::SignDeterministic(
            child_secret_key, *leaf_index, message,
            share.authenticated_signature.signature)) {
        return Failure(error, ChainLockSigningError::SIGNING_FAILURE);
    }
    PQChildSignature journal_signature;
    std::copy(share.authenticated_signature.signature.begin(),
              share.authenticated_signature.signature.end(),
              journal_signature.begin());
    const PQSignerJournalResult stored{m_journal.StoreSignature(
        journal_key, message_hash, journal_signature)};
    if (stored.outcome != PQSignerJournalOutcome::STORED &&
        stored.outcome != PQSignerJournalOutcome::REPLAY) {
        return Failure(error, MapJournalError(stored.outcome));
    }
    if (stored.outcome == PQSignerJournalOutcome::REPLAY) {
        if (!stored.signature) {
            return Failure(error, ChainLockSigningError::JOURNAL_FAILURE);
        }
        std::copy(stored.signature->begin(), stored.signature->end(),
                  share.authenticated_signature.signature.begin());
    }
    return {.share = std::move(share), .replayed = false};
}

} // namespace llmq::pq
