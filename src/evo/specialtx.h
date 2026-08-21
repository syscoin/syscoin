// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_SPECIALTX_H
#define SYSCOIN_EVO_SPECIALTX_H

#include <evo/specialtx_payload.h>
#include <kernel/cs_main.h>

#include <cstdint>

class CBlock;
class CBlockIndex;
class uint256;
class TxValidationState;
class BlockValidationState;
class CCoinsViewCache;
class ChainstateManager;
class CDeterministicMNListNEVMAddressDiff;
namespace node {
class BlockManager;
}
enum class SpecialTxValidationContext : uint8_t {
    NORMAL,
    /** Cheap pre-script mempool pass; NORMAL authentication must follow. */
    MEMPOOL_PRECHECK,
    /**
     * Structural block precheck for updates whose cryptographic authorization
     * is owned by the PQ registry state transition later in the same call.
     */
    PQ_REGISTRY_PRECHECK,
    /** Only Chainstate::RollforwardBlock may reuse an earlier validation. */
    ALREADY_VALIDATED_ROLLFORWARD,
};

bool CheckSpecialTx(node::BlockManager &blockman, const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool ProcessSpecialTxsInBlock(ChainstateManager &chainman, const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state, CDeterministicMNListNEVMAddressDiff &diff, CCoinsViewCache& view, bool fJustCheck, bool check_sigs, bool ibd, SpecialTxValidationContext validation_context) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CDeterministicMNListNEVMAddressDiff& diffNEVM, bool bUpdateSpecialTxState, bool bReplay) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

#endif // SYSCOIN_EVO_SPECIALTX_H
