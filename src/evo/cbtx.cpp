// Copyright (c) 2017-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/cbtx.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <univalue.h>
#include <validation.h>
#include <util/time.h>
#include <logging.h>

bool CheckCbTxBestChainlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state, bool fJustCheck)
{
    if (block.vtx[0]->nVersion != SYSCOIN_TX_VERSION_MN_CLSIG) {
        return true;
    }
    // atleast 2 CLSIG validation per DKG interval for transitions to validate in ZK light client
    const auto& nMidDKGHeight = Params().GetConsensus().llmqTypeChainLocks.dkgInterval/2;
    const auto &nModHeight = nMidDKGHeight - nMidDKGHeight%5;
    if ((pindex->pprev->nHeight % nModHeight) != 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-height");
    }
    CCbTxCLSIG cbTx;
    if (!GetTxPayload(*block.vtx[0], cbTx)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-payload");
    }
    if (cbTx.nVersion != CCbTxCLSIG::CURRENT_VERSION) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-cbtx-version");
    }
    llmq::CChainLockSig bestCL;
    if(!CalcCbTxBestChainlock(pindex->pprev, bestCL)) {
        // if local node has chainlock enforce miner to include the same one otherwise CL can be null (no CL's forming)
        if(!cbTx.cl.IsNull()) {
            // no chainlock found so we cannot enforce, instead just verify correctness
            const auto curBlockCoinbaseCLIndex = pindex->GetAncestor(cbTx.cl.nHeight);
            if (!llmq::chainLocksHandler->VerifyAggregatedChainLock(cbTx.cl, curBlockCoinbaseCLIndex)) {
                return state.Invalid(BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE, "bad-cbtx-invalid-clsig");
            }
        }
        return true;
    }
    LogPrintf("CheckCbTxBestChainlock check cl matc bestCL %s\n", bestCL.ToString());
    // here we have a locked chain with chainlock so we make sure the CLSIG in the chain matches our locked chain
    if(cbTx.cl != bestCL) {
        return state.Invalid(BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE, "bad-cbtx-clsig");
    }
    return true;
}

bool CalcCbTxBestChainlock(const CBlockIndex* pindexPrev, llmq::CChainLockSig& bestCL)
{
    const auto best_clsig = llmq::chainLocksHandler->GetBestChainLock();
    if (!best_clsig.IsNull() && best_clsig.blockHash == pindexPrev->GetAncestor(pindexPrev->nHeight - 5)->GetBlockHash()) {
        // Our best CL is the newest one possible
        bestCL = best_clsig;
        return true;
    }
    return false;
}


std::string CCbTxCLSIG::ToString() const
{
    return strprintf("CCbTxCLSIG(nVersion=%d, cl=%s)",
        static_cast<uint16_t>(nVersion), cl.ToString());
}