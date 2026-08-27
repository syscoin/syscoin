// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_VERIFY_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_VERIFY_H

#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_payment_audit.h>

#include <array>
#include <memory>
#include <optional>
#include <vector>

namespace llmq::pq {

enum class PaymentAuditVerificationError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_AUDIT,
    INVALID_SEAL,
    INVALID_CONTEXT,
    INVALID_SIGNER,
    INVALID_CHILD_PROOF,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE,
};

/** Immutable proof that one exact live audit context passed full validation. */
class PreparedPaymentAuditContext final {
public:
    [[nodiscard]] static std::shared_ptr<const PreparedPaymentAuditContext>
    Create(const uint256& genesis_hash,
           PaymentAuditScheduleConfig schedule,
           PaymentAuditStatement statement,
           const FinalChainLock& seal_chainlock,
           FrozenQuorumRostersPtr rosters,
           uint8_t authorization_mask,
           PaymentAuditVerificationError* error = nullptr);

    [[nodiscard]] const uint256& GenesisHash() const noexcept
    {
        return m_seal_context->GenesisHash();
    }
    [[nodiscard]] const PaymentAuditScheduleConfig& Schedule() const noexcept
    {
        return m_schedule;
    }
    [[nodiscard]] const PaymentAuditStatement& Statement() const noexcept
    {
        return m_statement;
    }
    [[nodiscard]] const FrozenQuorumRosters& Rosters() const noexcept
    {
        return m_seal_context->Rosters();
    }
    [[nodiscard]] const FrozenQuorumRostersPtr& RostersPtr() const noexcept
    {
        return m_seal_context->RostersPtr();
    }
    [[nodiscard]] uint8_t AuthorizationMask() const noexcept
    {
        return m_seal_context->AuthorizationMask();
    }
    [[nodiscard]] std::optional<std::size_t> FindQuorumSlot(
        const PaymentAuditShareTranscript& transcript) const noexcept;
    [[nodiscard]] std::optional<uint8_t> LeafIndex(
        std::size_t quorum_slot) const noexcept
    {
        return quorum_slot < m_leaf_indices.size()
            ? m_leaf_indices[quorum_slot]
            : std::nullopt;
    }

private:
    PreparedPaymentAuditContext(
        PaymentAuditScheduleConfig schedule,
        PaymentAuditStatement statement,
        PreparedChainLockContextPtr seal_context,
        std::array<std::optional<uint8_t>, ACTIVE_QUORUMS> leaf_indices);

    PaymentAuditScheduleConfig m_schedule;
    PaymentAuditStatement m_statement;
    PreparedChainLockContextPtr m_seal_context;
    std::array<std::optional<uint8_t>, ACTIVE_QUORUMS> m_leaf_indices;
};

using PreparedPaymentAuditContextPtr =
    std::shared_ptr<const PreparedPaymentAuditContext>;

struct PreparedPaymentAuditVerification {
    std::vector<ScheduledWOTSCheck> checks;
};

[[nodiscard]] std::optional<ScheduledWOTSCheck>
PreparePaymentAuditResponseVerification(
    const uint256& genesis_hash,
    const ChainLockScheduleConfig& schedule,
    const PaymentAuditResponse& response,
    const PaymentAuditHave& expected,
    const FrozenQuorumRosters& response_rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error = nullptr);

/** Prepare one response against its exact prevalidated ordinary ChainLock. */
[[nodiscard]] std::optional<ScheduledWOTSCheck>
PreparePaymentAuditResponseVerification(
    const PaymentAuditResponse& response,
    const PaymentAuditHave& expected,
    const PreparedChainLockContext& response_context,
    PaymentAuditVerificationError* error = nullptr);

/** Whether a newly authoritative final statement is the prepared A context. */
[[nodiscard]] bool MatchesPaymentAuditResponseContext(
    const PaymentAuditHave& expected,
    const PreparedChainLockContext& response_context,
    const ChainLockStatement& finalized_statement);

[[nodiscard]] bool ValidatePaymentAuditContext(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const PaymentAuditStatement& statement,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error = nullptr);

/** Live-only gate: B must already have the exact ordinary ChainLock witness. */
[[nodiscard]] bool ValidatePaymentAuditLiveSeal(
    const uint256& genesis_hash,
    const PaymentAuditStatement& statement,
    const FinalChainLock& seal_chainlock,
    PaymentAuditVerificationError* error = nullptr);

[[nodiscard]] PaymentAuditShareTranscript BuildPaymentAuditShareTranscript(
    const PaymentAuditStatement& statement,
    const QuorumBitmap& reporter_observed_members,
    const QuorumDescriptor& descriptor,
    uint16_t member_index,
    const uint256& member_pro_tx_hash);

[[nodiscard]] std::optional<ScheduledWOTSCheck>
PreparePaymentAuditShareVerification(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const PaymentAuditShare& share,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error = nullptr);

/** Prepare one share against an already validated exact live audit context. */
[[nodiscard]] std::optional<ScheduledWOTSCheck>
PreparePaymentAuditShareVerification(
    const PaymentAuditShare& share,
    const PreparedPaymentAuditContext& context,
    PaymentAuditVerificationError* error = nullptr);

[[nodiscard]] std::optional<PreparedPaymentAuditVerification>
PrepareFinalPaymentAuditVerification(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const FinalPaymentAudit& audit,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    PaymentAuditVerificationError* error = nullptr);

[[nodiscard]] bool VerifyFinalPaymentAudit(
    const uint256& genesis_hash,
    const PaymentAuditScheduleConfig& schedule,
    const FinalPaymentAudit& audit,
    const FrozenQuorumRosters& rosters,
    uint8_t authorization_mask,
    ScheduledWOTSCheckQueue* queue = nullptr,
    PaymentAuditVerificationError* error = nullptr);

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_VERIFY_H
