// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_SIGNER_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_SIGNER_H

#include <llmq/pq_chainlock_signer.h>
#include <llmq/pq_payment_audit_verify.h>

namespace llmq::pq {

struct PaymentAuditSigningResult {
    std::optional<PaymentAuditShare> share;
    bool replayed{false};
};

/**
 * Purpose-separated signer consuming an exact prepared live-seal context.
 * Runtime generation and current-chain authorization remain caller-owned.
 */
class PaymentAuditShareSigner final {
public:
    PaymentAuditShareSigner(uint256 genesis_hash,
                            uint256 local_pro_tx_hash,
                            PaymentAuditScheduleConfig schedule,
                            CPQSignerJournal& journal);

    [[nodiscard]] PaymentAuditSigningResult Sign(
        const PreparedPaymentAuditContext& context,
        const QuorumBitmap& reporter_observed_members,
        uint8_t quorum_slot,
        uint16_t member_index,
        const scheduled_wots::SecretKey& child_secret_key,
        const ChildKeyProof& child_key_proof,
        const std::optional<PQSignerBranchLock>& expected_accepted_certificate,
        ChainLockSigningError* error = nullptr);

private:
    uint256 m_genesis_hash;
    uint256 m_local_pro_tx_hash;
    PaymentAuditScheduleConfig m_schedule;
    CPQSignerJournal& m_journal;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_SIGNER_H
