// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_COLLECTOR_H
#define SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_COLLECTOR_H

#include <llmq/pq_chainlock_collector.h>
#include <llmq/pq_payment_audit_verify.h>

#include <array>
#include <map>
#include <memory>
#include <optional>

namespace llmq::pq {

/** Bounded collector for one common audit statement with signer-specific reports. */
class PaymentAuditCollector final {
public:
    static std::unique_ptr<PaymentAuditCollector> Create(
        const uint256& genesis_hash,
        PaymentAuditScheduleConfig schedule,
        PaymentAuditStatement statement,
        const FinalChainLock& seal_chainlock,
        FrozenQuorumRostersPtr rosters,
        uint8_t authorization_mask,
        ShareCollectionError* error = nullptr);

    static std::unique_ptr<PaymentAuditCollector> Create(
        PreparedPaymentAuditContextPtr context,
        ShareCollectionError* error = nullptr);

    PaymentAuditCollector(const PaymentAuditCollector&) = delete;
    PaymentAuditCollector& operator=(const PaymentAuditCollector&) = delete;

    [[nodiscard]] ShareCollectionResult AddVerifiedShare(
        const PaymentAuditShare& share,
        ShareCollectionError* error = nullptr);
    [[nodiscard]] std::array<std::size_t, ACTIVE_QUORUMS>
    ShareCounts() const;
    [[nodiscard]] bool IsComplete() const;
    [[nodiscard]] std::optional<FinalPaymentAudit> Finalize() const;

private:
    explicit PaymentAuditCollector(PreparedPaymentAuditContextPtr context);

    PreparedPaymentAuditContextPtr m_context;
    std::array<std::map<uint16_t, PaymentAuditReportWitness>,
               ACTIVE_QUORUMS> m_shares;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_COLLECTOR_H
