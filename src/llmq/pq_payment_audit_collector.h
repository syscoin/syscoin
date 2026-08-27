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

namespace llmq_tests {
class PaymentAuditCollectorTestAccess;
}

namespace llmq::pq {

class PaymentAuditCollector;

/**
 * Process-local proof that one exact audit was assembled exclusively from
 * shares verified against one exact prepared context. This does not prove that
 * the context is still live or authorize durable archive publication.
 */
class CollectedPaymentAuditFinalization final {
public:
    CollectedPaymentAuditFinalization(
        const CollectedPaymentAuditFinalization&) = delete;
    CollectedPaymentAuditFinalization& operator=(
        const CollectedPaymentAuditFinalization&) = delete;

    [[nodiscard]] const FinalPaymentAudit& Certificate() const noexcept
    {
        return m_certificate;
    }
    [[nodiscard]] const PreparedPaymentAuditContextPtr& ContextPtr() const noexcept
    {
        return m_context;
    }

private:
    CollectedPaymentAuditFinalization(
        FinalPaymentAudit certificate,
        PreparedPaymentAuditContextPtr context);

    const FinalPaymentAudit m_certificate;
    const PreparedPaymentAuditContextPtr m_context;

    friend class PaymentAuditCollector;
};

using CollectedPaymentAuditFinalizationPtr =
    std::shared_ptr<const CollectedPaymentAuditFinalization>;

/** Bounded collector for one common audit statement with signer-specific reports. */
class PaymentAuditCollector final {
public:
    class ShareVerificationReservation final {
    public:
        ShareVerificationReservation(
            ShareVerificationReservation&&) noexcept = default;
        ShareVerificationReservation& operator=(
            ShareVerificationReservation&&) = delete;
        ShareVerificationReservation(
            const ShareVerificationReservation&) = delete;
        ShareVerificationReservation& operator=(
            const ShareVerificationReservation&) = delete;

    private:
        enum class VerificationState : uint8_t {
            PENDING = 0,
            VALID,
            INVALID,
        };

        ShareVerificationReservation(
            PreparedPaymentAuditContextPtr context,
            std::shared_ptr<const uint8_t> collector_token,
            PaymentAuditShare share,
            std::size_t quorum_slot,
            uint16_t member_index);

        PreparedPaymentAuditContextPtr m_context;
        std::shared_ptr<const uint8_t> m_collector_token;
        PaymentAuditShare m_share;
        std::size_t m_quorum_slot{0};
        uint16_t m_member_index{0};
        VerificationState m_verification_state{VerificationState::PENDING};
        ShareCollectionError m_verification_error{ShareCollectionError::NONE};

        friend class PaymentAuditCollector;
    };

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

    /**
     * Claim one signer slot before expensive crypto. The caller must complete
     * the reservation or retire this exact collector instance.
     */
    [[nodiscard]] std::optional<ShareVerificationReservation>
    ReserveShareVerification(
        const PaymentAuditShare& share,
        ShareCollectionError* error = nullptr);

    /** Execute child-proof and WOTS verification without collector access. */
    static void VerifyReservedShare(
        ShareVerificationReservation& reservation);

    /** Consume one exact claim and either insert its witness or release it. */
    [[nodiscard]] ShareCollectionResult CompleteShareVerification(
        ShareVerificationReservation reservation,
        ShareCollectionError* error = nullptr);

    [[nodiscard]] ShareCollectionResult AddVerifiedShare(
        const PaymentAuditShare& share,
        ShareCollectionError* error = nullptr);
    [[nodiscard]] std::array<std::size_t, ACTIVE_QUORUMS>
    ShareCounts() const;
    [[nodiscard]] bool HasAcceptedShare(
        const PaymentAuditShareTranscript& transcript) const noexcept;
    [[nodiscard]] bool IsComplete() const;
    [[nodiscard]] std::optional<FinalPaymentAudit> Finalize() const;
    [[nodiscard]] CollectedPaymentAuditFinalizationPtr
    FinalizeCollection() const;
    [[nodiscard]] PreparedPaymentAuditContextPtr
    GetPreparedContext() const noexcept
    {
        return m_context;
    }

private:
    explicit PaymentAuditCollector(PreparedPaymentAuditContextPtr context);

    [[nodiscard]] std::optional<FinalPaymentAudit>
    BuildFinalCertificate() const;

    PreparedPaymentAuditContextPtr m_context;
    std::shared_ptr<const uint8_t> m_instance_token;
    std::array<QuorumBitmap, ACTIVE_QUORUMS> m_pending_shares{};
    std::array<std::map<uint16_t, PaymentAuditReportWitness>,
               ACTIVE_QUORUMS> m_shares;

    friend class ::llmq_tests::PaymentAuditCollectorTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_PAYMENT_AUDIT_COLLECTOR_H
