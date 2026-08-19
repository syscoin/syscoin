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
    static std::unique_ptr<ChainLockCollector> Create(
        const uint256& genesis_hash,
        ChainLockStatement statement,
        FrozenQuorumRostersPtr rosters,
        uint8_t authorization_mask,
        ShareCollectionError* error = nullptr);

    ChainLockCollector(const ChainLockCollector&) = delete;
    ChainLockCollector& operator=(const ChainLockCollector&) = delete;

    [[nodiscard]] ShareCollectionResult AddVerifiedShare(
        const ChainLockShare& share,
        ShareCollectionError* error = nullptr);

    [[nodiscard]] std::array<std::size_t, ACTIVE_QUORUMS> ShareCounts() const;
    [[nodiscard]] bool IsComplete() const;

    /** Select the lowest three ready quorum slots and first 267 member indices. */
    [[nodiscard]] std::optional<FinalChainLock> Finalize() const;

    [[nodiscard]] const ChainLockStatement& GetStatement() const noexcept
    {
        return m_statement;
    }

private:
    ChainLockCollector(
        uint256 genesis_hash,
        ChainLockStatement statement,
        FrozenQuorumRostersPtr rosters,
        uint8_t authorization_mask);

    [[nodiscard]] std::optional<std::size_t> FindQuorumSlot(
        const ChainLockShareTranscript& transcript) const;

    uint256 m_genesis_hash;
    ChainLockStatement m_statement;
    FrozenQuorumRostersPtr m_rosters;
    uint8_t m_authorization_mask{0};
    std::array<std::map<uint16_t, AuthenticatedChildSignature>,
               ACTIVE_QUORUMS> m_shares;

    friend class ::llmq_tests::ChainLockCollectorTestAccess;
};

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHAINLOCK_COLLECTOR_H
