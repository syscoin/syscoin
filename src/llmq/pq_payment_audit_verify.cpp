// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_verify.h>

#include <algorithm>

namespace llmq::pq {
namespace {

void SetError(PaymentAuditVerificationError* error,
              PaymentAuditVerificationError value)
{
    if (error != nullptr) *error = value;
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t member)
{
    return (bitmap[member / 8] &
            static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0;
}

bool IsSelected(uint8_t mask, std::size_t slot)
{
    return (mask & (uint8_t{1} << slot)) != 0;
}

std::optional<std::size_t> FindQuorumSlot(
    const PaymentAuditShareTranscript& transcript,
    const FrozenQuorumRosters& rosters)
{
    for (std::size_t slot{0}; slot < rosters.size(); ++slot) {
        const auto& descriptor{rosters[slot].descriptor};
        if (descriptor.epoch == transcript.quorum_epoch &&
            descriptor.base_hash == transcript.quorum_base_hash) {
            return slot;
        }
    }
    return std::nullopt;
}

std::optional<ScheduledWOTSCheck> PrepareSignatureCheck(
    const uint256& genesis_hash,
    uint8_t leaf_index,
    const PaymentAuditShareTranscript& transcript,
    const AuthenticatedChildSignature& authenticated,
    const FrozenQuorumMember& member,
    uint32_t quorum_epoch,
    PaymentAuditVerificationError* error)
{
    if (!member.eligible || !member.child_root ||
        member.pro_tx_hash != transcript.member_pro_tx_hash) {
        SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    if (!VerifyCommittedChildKeyProof(
            genesis_hash, member.child_root->commitment, quorum_epoch,
            authenticated.key_proof)) {
        SetError(error, PaymentAuditVerificationError::INVALID_CHILD_PROOF);
        return std::nullopt;
    }
    scheduled_wots::PublicKey public_key{
        authenticated.key_proof.public_key};
    const uint256 share_hash{
        GetPaymentAuditShareHash(genesis_hash, transcript)};
    scheduled_wots::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    scheduled_wots::Signature signature;
    std::copy(authenticated.signature.begin(), authenticated.signature.end(),
              signature.begin());
    return ScheduledWOTSCheck{std::move(public_key), leaf_index,
                              std::move(message), std::move(signature)};
}

} // namespace

std::optional<ScheduledWOTSCheck>
PreparePaymentAuditResponseVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const PaymentAuditResponse& response,
    const PaymentAuditHave& expected,
    const FrozenQuorumRosters& response_rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error)
{
    SetError(error, PaymentAuditVerificationError::NONE);
    if (genesis_hash.IsNull() || !response.IsStructurallyValid() ||
        !expected.IsStructurallyValid() || response.epoch != expected.epoch ||
        response.row_index != expected.row_index ||
        response.subject_descriptor_hash !=
            expected.subject_descriptor_hash ||
        response.response.transcript.height != expected.response_height ||
        GetLogicalChainLockId(genesis_hash,
                              response.response.GetStatement()) !=
            expected.response_chainlock_logical_id) {
        SetError(error, PaymentAuditVerificationError::INVALID_AUDIT);
        return std::nullopt;
    }
    const auto& subject{response_rosters.back()};
    if (subject.descriptor.epoch != response.epoch ||
        GetPaymentAuditDescriptorHash(genesis_hash, subject.descriptor) !=
            response.subject_descriptor_hash ||
        response.response.transcript.quorum_epoch !=
            subject.descriptor.epoch ||
        response.response.transcript.quorum_base_hash !=
            subject.descriptor.base_hash) {
        SetError(error, PaymentAuditVerificationError::INVALID_CONTEXT);
        return std::nullopt;
    }
    ChainLockVerificationError chainlock_error{
        ChainLockVerificationError::NONE};
    auto check{PrepareChainLockShareVerification(
        genesis_hash, schedule, response.response, response_rosters,
        authorization_mask,
        &chainlock_error)};
    if (!check) {
        switch (chainlock_error) {
        case ChainLockVerificationError::INVALID_PUBLIC_KEY:
            SetError(error, PaymentAuditVerificationError::INVALID_PUBLIC_KEY);
            break;
        case ChainLockVerificationError::INVALID_CHILD_PROOF:
            SetError(error,
                     PaymentAuditVerificationError::INVALID_CHILD_PROOF);
            break;
        default:
            SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
            break;
        }
        return std::nullopt;
    }
    return check;
}

bool ValidatePaymentAuditContext(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const PaymentAuditStatement& statement,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error)
{
    SetError(error, PaymentAuditVerificationError::NONE);
    const auto audit_schedule{BuildPaymentAuditEpochSchedule(
        schedule, statement.commitment.subject_epoch)};
    if (genesis_hash.IsNull() || !schedule.IsValid() ||
        !statement.IsStructurallyValid() || !audit_schedule ||
        audit_schedule->seal_height != statement.commitment.seal_height) {
        SetError(error, PaymentAuditVerificationError::INVALID_ARGUMENT);
        return false;
    }
    ChainLockVerificationError context_error{
        ChainLockVerificationError::NONE};
    if (!ValidateFrozenQuorumContext(genesis_hash,
                                     statement.seal_statement, rosters,
                                     authorization_mask,
                                     &context_error)) {
        SetError(error, PaymentAuditVerificationError::INVALID_CONTEXT);
        return false;
    }
    return true;
}

bool ValidatePaymentAuditLiveSeal(
    const uint256& genesis_hash,
    const PaymentAuditStatement& statement,
    const FinalChainLock& seal_chainlock,
    PaymentAuditVerificationError* error)
{
    SetError(error, PaymentAuditVerificationError::NONE);
    if (genesis_hash.IsNull() || !statement.IsStructurallyValid() ||
        !seal_chainlock.IsStructurallyValid() ||
        seal_chainlock.statement != statement.seal_statement ||
        seal_chainlock.GetLogicalId(genesis_hash).IsNull()) {
        SetError(error, PaymentAuditVerificationError::INVALID_SEAL);
        return false;
    }
    return true;
}

PaymentAuditShareTranscript BuildPaymentAuditShareTranscript(
    const PaymentAuditStatement& statement,
    const QuorumBitmap& reporter_observed_members,
    const QuorumDescriptor& descriptor,
    uint16_t member_index,
    const uint256& member_pro_tx_hash)
{
    return PaymentAuditShareTranscript{
        statement, reporter_observed_members, descriptor.epoch,
        descriptor.base_hash, member_index, member_pro_tx_hash};
}

std::optional<ScheduledWOTSCheck> PreparePaymentAuditShareVerification(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const PaymentAuditShare& share,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error)
{
    SetError(error, PaymentAuditVerificationError::NONE);
    if (!share.IsStructurallyValid()) {
        SetError(error, PaymentAuditVerificationError::INVALID_AUDIT);
        return std::nullopt;
    }
    const auto slot{FindQuorumSlot(share.transcript, rosters)};
    if (!slot ||
        (authorization_mask & (uint8_t{1} << *slot)) == 0) {
        SetError(error, PaymentAuditVerificationError::INVALID_CONTEXT);
        return std::nullopt;
    }
    if (share.transcript.member_index >= QUORUM_SIZE) {
        SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    if (!ValidatePaymentAuditContext(genesis_hash, schedule,
                                     share.transcript.statement, rosters,
                                     authorization_mask, error)) {
        return std::nullopt;
    }
    const auto& roster{rosters[*slot]};
    const auto leaf_index{PaymentAuditLeafIndex(
        schedule, share.transcript.statement.commitment.subject_epoch,
        share.transcript.statement.commitment.seal_height,
        roster.descriptor.epoch)};
    const std::size_t member_index{share.transcript.member_index};
    if (roster.descriptor.valid_count < QUORUM_MIN_VALID ||
        !IsBitSet(roster.descriptor.valid_members, member_index) ||
        !leaf_index) {
        SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    return PrepareSignatureCheck(
        genesis_hash, *leaf_index, share.transcript,
        share.authenticated_signature,
        roster.members[member_index], roster.descriptor.epoch, error);
}

std::optional<PreparedPaymentAuditVerification>
PrepareFinalPaymentAuditVerification(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const FinalPaymentAudit& audit,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error)
{
    SetError(error, PaymentAuditVerificationError::NONE);
    if (!audit.IsStructurallyValid()) {
        SetError(error, PaymentAuditVerificationError::INVALID_AUDIT);
        return std::nullopt;
    }
    if ((audit.selected_quorum_mask & ~authorization_mask) != 0) {
        SetError(error, PaymentAuditVerificationError::INVALID_CONTEXT);
        return std::nullopt;
    }
    if (!ValidatePaymentAuditContext(genesis_hash, schedule, audit.statement,
                                     rosters, authorization_mask, error)) {
        return std::nullopt;
    }

    PreparedPaymentAuditVerification prepared;
    prepared.checks.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    std::size_t report_index{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if (!IsSelected(audit.selected_quorum_mask, slot)) continue;
        const auto& roster{rosters[slot]};
        const auto leaf_index{PaymentAuditLeafIndex(
            schedule, audit.statement.commitment.subject_epoch,
            audit.statement.commitment.seal_height,
            roster.descriptor.epoch)};
        if (roster.descriptor.valid_count < QUORUM_MIN_VALID ||
            !leaf_index) {
            SetError(error, PaymentAuditVerificationError::INVALID_CONTEXT);
            return std::nullopt;
        }
        for (std::size_t member_index{0}; member_index < QUORUM_SIZE;
             ++member_index) {
            if (!IsBitSet(audit.signer_bitmaps[slot], member_index)) continue;
            if (!IsBitSet(roster.descriptor.valid_members, member_index) ||
                report_index >= audit.report_witnesses.size()) {
                SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
                return std::nullopt;
            }
            const auto& witness{audit.report_witnesses[report_index]};
            const auto transcript{BuildPaymentAuditShareTranscript(
                audit.statement, witness.observed_members,
                roster.descriptor,
                static_cast<uint16_t>(member_index),
                roster.members[member_index].pro_tx_hash)};
            auto check{PrepareSignatureCheck(
                genesis_hash, *leaf_index, transcript,
                witness.authenticated_signature,
                roster.members[member_index], roster.descriptor.epoch, error)};
            if (!check) return std::nullopt;
            prepared.checks.push_back(std::move(*check));
            ++report_index;
        }
    }
    if (report_index != PAYMENT_AUDIT_SIGNATURE_COUNT ||
        prepared.checks.size() != PAYMENT_AUDIT_SIGNATURE_COUNT) {
        SetError(error, PaymentAuditVerificationError::INVALID_SIGNER);
        return std::nullopt;
    }
    return prepared;
}

bool VerifyFinalPaymentAudit(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const FinalPaymentAudit& audit,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    ScheduledWOTSCheckQueue* queue,
    PaymentAuditVerificationError* error)
{
    auto prepared{PrepareFinalPaymentAuditVerification(
        genesis_hash, schedule, audit, rosters, authorization_mask, error)};
    if (!prepared) return false;
    if (!VerifyScheduledWOTSChecks(std::move(prepared->checks), queue)) {
        SetError(error, PaymentAuditVerificationError::INVALID_SIGNATURE);
        return false;
    }
    SetError(error, PaymentAuditVerificationError::NONE);
    return true;
}

} // namespace llmq::pq
