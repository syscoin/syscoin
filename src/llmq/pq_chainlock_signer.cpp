// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_signer.h>

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
        return ChainLockSigningError::JOURNAL_CONFLICT;
    case PQSignerJournalOutcome::CONSUMED:
        return ChainLockSigningError::JOURNAL_CONSUMED;
    case PQSignerJournalOutcome::CAP_EXHAUSTED:
        return ChainLockSigningError::USAGE_CAP_EXHAUSTED;
    case PQSignerJournalOutcome::BRANCH_CONFLICT:
        return ChainLockSigningError::JOURNAL_CONFLICT;
    case PQSignerJournalOutcome::INVALID_ARGUMENT:
        return ChainLockSigningError::INVALID_ARGUMENT;
    default:
        return ChainLockSigningError::JOURNAL_FAILURE;
    }
}

ChainLockSigningResult Failure(ChainLockSigningError* error,
                               ChainLockSigningError value)
{
    SetError(error, value);
    return {};
}

} // namespace

ChainLockShareSigner::ChainLockShareSigner(
    uint256 genesis_hash,
    uint256 local_pro_tx_hash,
    ChainLockScheduleConfig schedule,
    CPQSignerJournal& journal)
    : m_genesis_hash{std::move(genesis_hash)},
      m_local_pro_tx_hash{std::move(local_pro_tx_hash)},
      m_schedule{schedule},
      m_journal{journal}
{
}

ChainLockSigningResult ChainLockShareSigner::Sign(
    const ChainLockStatement& statement,
    const std::array<FrozenQuorumRoster, ACTIVE_QUORUMS>& rosters,
    uint8_t authorization_mask,
    uint8_t quorum_slot,
    uint16_t member_index,
    const sphincs_c11::SecretKey& child_secret_key,
    const ChildKeyProof& child_key_proof,
    const std::optional<PQSignerBranchLock>& expected_branch_lock,
    ChainLockSigningError* error)
{
    SetError(error, ChainLockSigningError::NONE);
    if (m_genesis_hash.IsNull() || m_local_pro_tx_hash.IsNull() ||
        !statement.IsStructurallyValid() || !child_secret_key.IsInitialized()) {
        return Failure(error, ChainLockSigningError::INVALID_ARGUMENT);
    }
    if (!m_schedule.IsValid()) {
        return Failure(error, ChainLockSigningError::INVALID_SCHEDULE);
    }
    if (!IsEligibleChainLockTarget(m_schedule, statement.height)) {
        return Failure(error, ChainLockSigningError::INELIGIBLE_HEIGHT);
    }
    if (quorum_slot >= ACTIVE_QUORUMS) {
        return Failure(error, ChainLockSigningError::INVALID_QUORUM_SLOT);
    }
    if ((authorization_mask & (uint8_t{1} << quorum_slot)) == 0) {
        return Failure(error, ChainLockSigningError::INACTIVE_QUORUM);
    }
    ChainLockVerificationError context_error{ChainLockVerificationError::NONE};
    if (!ValidateFrozenQuorumContext(m_genesis_hash, statement, rosters,
                                     authorization_mask,
                                     &context_error)) {
        return Failure(error, ChainLockSigningError::INVALID_CONTEXT);
    }
    const auto& roster{rosters[quorum_slot]};
    if (!IsEpochActiveForTarget(m_schedule, roster.descriptor.epoch,
                                statement.height) ||
        roster.descriptor.valid_count < QUORUM_MIN_VALID) {
        return Failure(error, ChainLockSigningError::INACTIVE_QUORUM);
    }
    if (member_index >= QUORUM_SIZE ||
        (roster.descriptor.valid_members[member_index / 8] &
         static_cast<uint8_t>(uint8_t{1} << (member_index % 8))) == 0) {
        return Failure(error, ChainLockSigningError::INVALID_MEMBER);
    }
    const auto& member{roster.members[member_index]};
    if (member.pro_tx_hash != m_local_pro_tx_hash) {
        return Failure(error, ChainLockSigningError::WRONG_OPERATOR);
    }
    if (!member.eligible || !member.child_root) {
        return Failure(error, ChainLockSigningError::INVALID_MEMBER);
    }
    if (!VerifyCommittedChildKeyProof(
            m_genesis_hash, member.child_root->commitment,
            roster.descriptor.epoch, child_key_proof) ||
        sphincs_c11::SerializePublicKey(child_secret_key.GetPublicKey()) !=
            child_key_proof.public_key) {
        return Failure(error, ChainLockSigningError::SECRET_KEY_MISMATCH);
    }

    FinalChainLock shell;
    shell.statement = statement;
    ChainLockShare share;
    share.transcript = BuildChainLockShareTranscript(
        shell, roster.descriptor, member_index, member.pro_tx_hash);
    share.authenticated_signature.key_proof = child_key_proof;
    if (!share.transcript.IsStructurallyValid()) {
        return Failure(error, ChainLockSigningError::INVALID_CONTEXT);
    }
    const uint256 message_hash{
        GetChainLockShareHash(m_genesis_hash, share.transcript)};
    const PQSignerJournalKey journal_key{
        .genesis_hash = m_genesis_hash,
        .child_profile = statement.child_profile,
        .pro_tx_hash = m_local_pro_tx_hash,
        .quorum_epoch = roster.descriptor.epoch,
        .child_key_hash = ::Hash(child_key_proof.public_key),
        .absolute_height = statement.height,
    };
    const PQSignerBranchLock candidate_branch_lock{
        statement.height,
        statement.block_hash,
        GetLogicalChainLockId(m_genesis_hash, statement)};

    const PQSignerJournalResult reservation{
        m_journal.Reserve(journal_key, message_hash, candidate_branch_lock,
                          expected_branch_lock)};
    if (reservation.outcome == PQSignerJournalOutcome::REPLAY) {
        if (!reservation.signature) {
            return Failure(error, ChainLockSigningError::JOURNAL_FAILURE);
        }
        std::copy(reservation.signature->begin(), reservation.signature->end(),
                  share.authenticated_signature.signature.begin());
        SetError(error, ChainLockSigningError::NONE);
        return {.share = std::move(share), .replayed = true};
    }
    if (reservation.outcome != PQSignerJournalOutcome::RESERVED) {
        return Failure(error, MapJournalError(reservation.outcome));
    }

    sphincs_c11::Message message;
    std::copy(message_hash.begin(), message_hash.end(), message.begin());
    if (!sphincs_c11::Sign(
            child_secret_key, message,
            share.authenticated_signature.signature)) {
        // The durable reservation intentionally remains consumed.
        return Failure(error, ChainLockSigningError::SIGNING_FAILURE);
    }
    PQC11Signature journal_signature;
    std::copy(share.authenticated_signature.signature.begin(),
              share.authenticated_signature.signature.end(),
              journal_signature.begin());
    const PQSignerJournalResult stored{
        m_journal.StoreSignature(journal_key, message_hash, journal_signature)};
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
    SetError(error, ChainLockSigningError::NONE);
    return {.share = std::move(share), .replayed = false};
}

} // namespace llmq::pq
