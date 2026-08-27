// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHAINLOCK_COLLECTOR_H
#define SYSCOIN_LLMQ_PQ_CHAINLOCK_COLLECTOR_H

#include <llmq/pq_chainlock_verify.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>

namespace llmq_tests {
class ChainLockCollectorTestAccess;
}

namespace llmq::pq {

class ChainLockCollector;

/**
 * Process-local proof that one exact certificate was assembled exclusively
 * from shares verified against one exact prepared context. This does not prove
 * that the context is still live or authorize durable finality publication.
 */
class CollectedChainLockFinalization final {
public:
    CollectedChainLockFinalization(
        const CollectedChainLockFinalization&) = delete;
    CollectedChainLockFinalization& operator=(
        const CollectedChainLockFinalization&) = delete;

    [[nodiscard]] const FinalChainLock& Certificate() const noexcept
    {
        return m_certificate;
    }
    [[nodiscard]] const PreparedChainLockContextPtr& ContextPtr() const noexcept
    {
        return m_context;
    }

private:
    CollectedChainLockFinalization(
        FinalChainLock certificate,
        PreparedChainLockContextPtr context);

    const FinalChainLock m_certificate;
    const PreparedChainLockContextPtr m_context;

    friend class ChainLockCollector;
};

using CollectedChainLockFinalizationPtr =
    std::shared_ptr<const CollectedChainLockFinalization>;

enum class ShareCollectionError : uint8_t {
    NONE = 0,
    INVALID_ARGUMENT,
    INVALID_CONTEXT,
    INVALID_SHARE,
    STATEMENT_MISMATCH,
    UNKNOWN_QUORUM,
    INVALID_MEMBER,
    DUPLICATE,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE,
    INVALID_CHILD_PROOF,
    LOCAL_ERROR,
};

enum class ShareCollectionResult : uint8_t {
    ACCEPTED = 0,
    DUPLICATE,
    REJECTED,
};

/**
 * Bounded collector for one logical ChainLock statement.
 *
 * It shares the immutable branch-derived context used for every share. At most
 * one signature is retained for each of the 1,600 roster slots, so
 * unauthenticated traffic cannot turn this object into an unbounded allocation
 * sink.
 */
class ChainLockCollector final {
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
            PreparedChainLockContextPtr context,
            std::shared_ptr<const uint8_t> collector_token,
            ChainLockShare share,
            std::size_t quorum_slot,
            uint16_t member_index);

        PreparedChainLockContextPtr m_context;
        std::shared_ptr<const uint8_t> m_collector_token;
        ChainLockShare m_share;
        std::size_t m_quorum_slot{0};
        uint16_t m_member_index{0};
        VerificationState m_verification_state{VerificationState::PENDING};
        ShareCollectionError m_verification_error{ShareCollectionError::NONE};

        friend class ChainLockCollector;
    };

    static std::unique_ptr<ChainLockCollector> Create(
        const uint256& genesis_hash,
        ChainLockScheduleConfig schedule,
        ChainLockStatement statement,
        FrozenQuorumRostersPtr rosters,
        uint8_t authorization_mask,
        ShareCollectionError* error = nullptr);

    static std::unique_ptr<ChainLockCollector> Create(
        PreparedChainLockContextPtr context,
        ShareCollectionError* error = nullptr);

    ChainLockCollector(const ChainLockCollector&) = delete;
    ChainLockCollector& operator=(const ChainLockCollector&) = delete;

    /**
     * Claim one signer slot before expensive crypto. The caller must complete
     * the reservation or retire this exact collector instance.
     */
    [[nodiscard]] std::optional<ShareVerificationReservation>
    ReserveShareVerification(
        const ChainLockShare& share,
        ShareCollectionError* error = nullptr);

    /** Execute child-proof and WOTS verification without collector access. */
    static void VerifyReservedShare(
        ShareVerificationReservation& reservation);

    /** Consume one exact claim and either insert its signature or release it. */
    [[nodiscard]] ShareCollectionResult CompleteShareVerification(
        ShareVerificationReservation reservation,
        ShareCollectionError* error = nullptr);

    [[nodiscard]] ShareCollectionResult AddVerifiedShare(
        const ChainLockShare& share,
        ShareCollectionError* error = nullptr);

    [[nodiscard]] std::array<std::size_t, ACTIVE_QUORUMS> ShareCounts() const;
    [[nodiscard]] bool IsComplete() const;

    /** Select the lowest three ready quorum slots and first 267 member indices. */
    [[nodiscard]] std::optional<FinalChainLock> Finalize() const;

    /**
     * Mint an opaque process-local proof for the exact finalized bytes and the
     * exact immutable context used by every accepted share.
     */
    [[nodiscard]] CollectedChainLockFinalizationPtr
    FinalizeCollection() const;

    [[nodiscard]] const ChainLockStatement& GetStatement() const noexcept
    {
        return m_context->Statement();
    }
    [[nodiscard]] PreparedChainLockContextPtr
    GetPreparedContext() const noexcept
    {
        return m_context;
    }

private:
    explicit ChainLockCollector(PreparedChainLockContextPtr context);

    [[nodiscard]] std::optional<FinalChainLock>
    BuildFinalCertificate() const;

    PreparedChainLockContextPtr m_context;
    std::shared_ptr<const uint8_t> m_instance_token;
    std::array<QuorumBitmap, ACTIVE_QUORUMS> m_pending_shares{};
    std::array<std::map<uint16_t, AuthenticatedChildSignature>,
               ACTIVE_QUORUMS> m_shares;

    friend class ::llmq_tests::ChainLockCollectorTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_COLLECTOR_H
