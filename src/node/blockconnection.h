// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NODE_BLOCKCONNECTION_H
#define SYSCOIN_NODE_BLOCKCONNECTION_H

#include <coins.h>
#include <consensus/validation.h>
#include <kernel/cs_main.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <util/hasher.h>

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace node {

struct BlockConnectionState {
    NEVMMintTxSet mint_txs;
    NEVMTxRootMap nevm_tx_roots;
    PoDAMAPMemory poda;
    std::vector<std::pair<uint256, uint32_t>> txid_pairs;
    std::unique_ptr<CCoinsViewCache> view;

    explicit BlockConnectionState(CCoinsViewCache& coins_tip)
        : view{std::make_unique<CCoinsViewCache>(&coins_tip)} {}

    void Reset(CCoinsViewCache& coins_tip, BlockValidationState& state)
    {
        view = std::make_unique<CCoinsViewCache>(&coins_tip);
        state = BlockValidationState{};
        mint_txs.clear();
        nevm_tx_roots.clear();
        poda.clear();
        txid_pairs.clear();
    }
};

enum class BlockConnectionResult {
    SUCCESS,
    FAILED,
    DISK_READ_FAILED,
};

// Auxiliary rejection must precede other stateful validation: this retry resets
// only the child coins view and the outputs staged by the connection attempt.
template <typename Connect>
BlockConnectionResult ConnectBlockWithAuxiliaryRetry(
    const BlockManager& blockman, const CBlockIndex& index, bool loaded_from_disk,
    std::shared_ptr<const CBlock>& block, BlockValidationState& state,
    CCoinsViewCache& coins_tip, BlockConnectionState& connection, Connect&& connect)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    bool connected = connect();
    if (!connected && loaded_from_disk && state.GetResult() == BlockValidationResult::BLOCK_AUX_DATA_INVALID &&
        HasNEVMAuxiliaryData(*block)) {
        // Disk blocks omit sidecars. Reread that representation rather than
        // treating the first in-memory representation as trusted block data.
        auto committed = std::make_shared<CBlock>();
        if (!blockman.ReadBlockFromDisk(*committed, index, /*load_auxiliary_data=*/false)) {
            return BlockConnectionResult::DISK_READ_FAILED;
        }
        connection.Reset(coins_tip, state);
        block = std::move(committed);
        connected = connect();
    }
    return connected ? BlockConnectionResult::SUCCESS : BlockConnectionResult::FAILED;
}

} // namespace node

#endif // SYSCOIN_NODE_BLOCKCONNECTION_H
