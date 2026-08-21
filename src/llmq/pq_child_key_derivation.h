// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H
#define SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H

#include <crypto/sphincs_c11/sphincs_c11.h>
#include <llmq/pq_chainlock_types.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace llmq::pq {

using ChainLockMasterSeed =
    std::array<unsigned char, sphincs_c11::SECRET_SEED_SIZE>;

/** Parse an exact, nonzero independent C11 master seed. */
[[nodiscard]] bool ImportChainLockMasterSeed(
    std::span<const uint8_t> encoded,
    ChainLockMasterSeed& output) noexcept;

/**
 * Derive a child key in a pre-transaction Merkle-tree domain.
 *
 * tree_id is committed on-chain and lets an operator build the tree before a
 * new ProRegTx has a transaction id. The quorum descriptor and share
 * transcript still bind the resulting key to the actual proTxHash.
 */
[[nodiscard]] std::optional<ChildPublicKey> DeriveCommittedChildPublicKey(
    std::span<const uint8_t> chainlock_master_seed,
    const uint256& genesis_hash,
    const uint256& tree_id,
    uint32_t generation,
    uint32_t epoch) noexcept;

} // namespace llmq::pq

#endif // SYSCOIN_LLMQ_PQ_CHILD_KEY_DERIVATION_H
