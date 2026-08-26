// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_VERIFY_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_VERIFY_H

#include <llmq/pq_chainlock_verify.h>
#include <llmq/pq_payment_audit.h>

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
