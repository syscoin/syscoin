// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_WALLET_PQ_KEY_SCHEDULE_H
#define SYSCOIN_WALLET_PQ_KEY_SCHEDULE_H

#include <llmq/pq_chainlock_types.h>

#include <cstdint>
#include <functional>
#include <optional>

namespace wallet {

/** A cutoff change requires a new tree, never relabeling an already-built root. */
inline std::optional<llmq::pq::ChildKeyTreeCommitment>
BuildCurrentPQChildKeyCommitment(
    const std::function<uint32_t()>& read_first_epoch,
    const std::function<llmq::pq::ChildKeyTreeCommitment(uint32_t)>& build)
{
    uint32_t first_epoch{read_first_epoch()};
    // One replacement handles an ordinary cutoff crossing without allowing
    // a fast-moving chain to keep an expensive wallet RPC running forever.
    for (int attempt{0}; attempt < 2; ++attempt) {
        auto commitment{build(first_epoch)};
        const uint32_t current_first_epoch{read_first_epoch()};
        if (commitment.first_epoch == current_first_epoch) return commitment;
        first_epoch = current_first_epoch;
    }
    return std::nullopt;
}

} // namespace wallet

#endif // SYSCOIN_WALLET_PQ_KEY_SCHEDULE_H
