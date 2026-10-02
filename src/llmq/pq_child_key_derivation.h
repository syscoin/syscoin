// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H
#define SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H

#include <llmq/pq_chainlock_types.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace llmq::pq {

inline constexpr std::size_t CHAINLOCK_MASTER_SEED_SIZE{32};
using ChainLockMasterSeed =
    std::array<unsigned char, CHAINLOCK_MASTER_SEED_SIZE>;

/** Parse an exact, nonzero independent child-key master seed. */
[[nodiscard]] bool ImportChainLockMasterSeed(
    std::span<const uint8_t> encoded,
    ChainLockMasterSeed& output) noexcept;

/**
 * Derive a child key in the on-chain Merkle-tree domain. Consensus derives
 * tree_id from the operator identity and tree schedule; the quorum descriptor
 * and share transcript also bind the resulting key to the proTxHash.
 */
[[nodiscard]] std::optional<ChildPublicKey> DeriveCommittedChildPublicKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& genesis_hash,
    const uint256& tree_id,
    uint32_t generation,
    uint32_t epoch) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H
