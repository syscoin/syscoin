// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_MASTERNODE_PQ_OPERATORKEYS_H
#define SYSCOIN_MASTERNODE_PQ_OPERATORKEYS_H

#include <crypto/slhdsa/slhdsa.h>
#include <crypto/scheduled_wots/scheduled_wots.h>
#include <llmq/pq_child_key_derivation.h>
#include <llmq/pq_child_key_tree.h>

#include <cstdint>
#include <optional>
#include <utility>

namespace llmq::pq {

/**
 * Process-local owner of the operator's long-lived SLH-DSA key.
 *
 * The secret is never exposed by this API. Only narrowly domain-separated
 * authorization signing and the independent-seed ChainLock child KDF are
 * available. Returned child keys are move-only and cleanse storage.
 */
class LocalOperatorKeyManager final {
public:
    LocalOperatorKeyManager(slhdsa::SecretKey&& global_secret_key,
                            ChainLockMasterSeed&& chainlock_master_seed);
    ~LocalOperatorKeyManager();

    LocalOperatorKeyManager(const LocalOperatorKeyManager&) = delete;
    LocalOperatorKeyManager& operator=(const LocalOperatorKeyManager&) = delete;
    LocalOperatorKeyManager(LocalOperatorKeyManager&& other) noexcept;
    LocalOperatorKeyManager& operator=(LocalOperatorKeyManager&& other) noexcept;

    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] const GlobalPublicKey& GetGlobalPublicKey() const noexcept
    {
        return m_global_public_key;
    }
    [[nodiscard]] bool Matches(const GlobalKeyRecord& record) const noexcept;

    [[nodiscard]] bool SignMNAUTH(const uint256& authorization_hash,
                                  GlobalSignature& signature) const noexcept;

    [[nodiscard]] bool SignGovernanceTrigger(
        const uint256& authorization_hash,
        GlobalSignature& signature) const noexcept;

    [[nodiscard]] bool SignGovernanceVote(
        const uint256& authorization_hash,
        GlobalSignature& signature) const noexcept;

    [[nodiscard]] bool SignGovernanceProposalVote(
        const uint256& authorization_hash,
        GlobalSignature& signature) const noexcept;

    [[nodiscard]] std::optional<scheduled_wots::SecretKey>
    DeriveCommittedChildKey(const uint256& genesis_hash,
                            const uint256& tree_id,
                            uint32_t generation,
                            uint32_t epoch) const noexcept;

    /** Expensive setup operation; callers must run it outside consensus and
     * network-processing paths. The resulting cache contains public data. */
    [[nodiscard]] std::optional<ChildKeyTree> BuildCommittedChildKeyTree(
        const ChildKeyTreeConfig& config,
        std::size_t worker_count,
        const std::atomic<bool>* cancel = nullptr) const;

private:
    slhdsa::SecretKey m_global_secret_key;
    GlobalPublicKey m_global_public_key{};
    ChainLockMasterSeed m_chainlock_master_seed{};
};

} // namespace llmq::pq

#endif // SYSCOIN_MASTERNODE_PQ_OPERATORKEYS_H
