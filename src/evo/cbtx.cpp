#include <evo/cbtx.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <llmq/quorums_signing.h>
#include <llmq/quorums.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <univalue.h>
#include <validation.h>
#include <util/time.h>
#include <logging.h>

// overall we are validating the transition between the aggregatedQuorumPubKeyHash which validates transition of DKG quorums from one to the next
// this is because the CLSIG in each interval will validate against any new quorums from each DKG session
bool CheckCbTxBestChainlock(ChainstateManager &chainman, const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state, bool fJustCheck)
{
    if (block.vtx[0]->nVersion != SYSCOIN_TX_VERSION_MN_CLSIG) {
        return true;
    }
    // this quorum period start
    const auto& nQuorumStartHeight = pindex->nHeight - (pindex->nHeight % Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    // last quorum period start
    const auto& nQuorumLastStartHeight = (nQuorumStartHeight - Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    // first possible height where CL would be gauranteed to be part of the last quorum period
    const auto& nQuorumLastMiningEnd = nQuorumLastStartHeight + Params().GetConsensus().llmqTypeChainLocks.dkgMiningWindowEnd + 1;
    // last possible block for last quorum period
    const auto& nLastDKGHeight = nQuorumStartHeight + Params().GetConsensus().llmqTypeChainLocks.dkgMiningWindowStart - 1;
    if (pindex->nHeight != nLastDKGHeight) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-mining-height");
    }
    // must have had no new quorums and thus the transition doesn't need to be checked
    if (!llmq::quorumBlockProcessor->HasMinedCommitment(pindex->GetAncestor(nQuorumLastStartHeight)->GetBlockHash())) {
        LogPrint(BCLog::CHAINLOCKS, "%s -- CLSIG (%s) mined commitment doesn't exist for this DKG interval, skipping checks...\n", __func__);
        return true;
    }
    CCbTxCLSIG cbTx;
    if (!GetTxPayload(*block.vtx[0], cbTx)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-payload");
    }
    if (cbTx.nVersion != CCbTxCLSIG::CURRENT_VERSION) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-version");
    }

    const auto latestChainLock = llmq::chainLocksHandler->GetBestChainLock();
    // if chainlock exists and it is part of this DKG interval validate that the CLSIG provided is valid and also part of this DKG interval
    if (!latestChainLock.IsNull() && latestChainLock.nHeight >= nQuorumLastMiningEnd && latestChainLock.nHeight <= nLastDKGHeight) {
        // Enforce non-null chainlocks if a valid local chainlock exists in this DKG interval
        if(cbTx.cl.IsNull()) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-missing-clsig");
        }
        if(!(cbTx.cl.nHeight >= nQuorumLastMiningEnd && cbTx.cl.nHeight <= nLastDKGHeight)) {
            LogPrint(BCLog::CHAINLOCKS, "%s -- CLSIG (%s) height must be between nQuorumLastMiningEnd (%d) and nLastDKGHeight (%d) but found %d\n", __func__, cbTx.cl.ToString(), nQuorumLastMiningEnd, nLastDKGHeight, cbTx.cl.nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-bad-height");
        }
        // simply check against local validated chainlock if not then try to accept block version which should be valid
        if (cbTx.cl != latestChainLock) {
            const auto chainLockBlockIndex = chainman.m_blockman.LookupBlockIndex(cbTx.cl.blockHash);
            if (!chainLockBlockIndex || !chainman.ActiveChain().Contains(chainLockBlockIndex) || !chainLockBlockIndex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return state.Invalid(BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE, "clsig-bad-block");
            }
            if(chainLockBlockIndex->nHeight != cbTx.cl.nHeight) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-height-mismatch");
            }
            if (!llmq::chainLocksHandler->VerifyAggregatedChainLock(cbTx.cl, chainLockBlockIndex, ::SerializeHash(cbTx.cl))) {
                LogPrint(BCLog::CHAINLOCKS, "%s -- invalid CLSIG (%s)\n", __func__, cbTx.cl.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-invalid-sig");
            }
        }
        return true;
    }
    // If no valid local chainlock, verify the chainlock in the block against the active chain
    else if (!cbTx.cl.IsNull()) {
        const auto chainLockBlockIndex = chainman.m_blockman.LookupBlockIndex(cbTx.cl.blockHash);
        if (!chainLockBlockIndex || !chainman.ActiveChain().Contains(chainLockBlockIndex) || !chainLockBlockIndex->IsValid(BLOCK_VALID_SCRIPTS)) {
            return state.Invalid(BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE, "clsig-bad-block");
        }
        if(!(cbTx.cl.nHeight >= nQuorumLastMiningEnd && cbTx.cl.nHeight <= nLastDKGHeight)) {
            LogPrint(BCLog::CHAINLOCKS, "%s -- CLSIG (%s) following active chain: height must be between nQuorumLastMiningEnd (%d) and nLastDKGHeight (%d) but found %d\n", __func__, cbTx.cl.ToString(), nQuorumLastMiningEnd, nLastDKGHeight, cbTx.cl.nHeight);
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-bad-height");
        }
        if(chainLockBlockIndex->nHeight != cbTx.cl.nHeight) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-height-mismatch");
        }
        if (!llmq::chainLocksHandler->VerifyAggregatedChainLock(cbTx.cl, chainLockBlockIndex, ::SerializeHash(cbTx.cl))) {
            LogPrint(BCLog::CHAINLOCKS, "%s -- invalid CLSIG (%s)\n", __func__, cbTx.cl.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-invalid-sig");
        }
        return true;
    }
    return true;
}

bool CalcCbTxBestChainlock(const CBlockIndex* pindexPrev, llmq::CChainLockSig& bestCL)
{
    int nHeight = pindexPrev->nHeight + 1;
    // this quorum period start
    const auto& nQuorumStartHeight = nHeight - (nHeight % Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    // last quorum period start
    const auto& nQuorumLastStartHeight = (nQuorumStartHeight - Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    // first possible height where CL would be gauranteed to be part of the last quorum period
    const auto& nQuorumLastMiningEnd = nQuorumLastStartHeight + Params().GetConsensus().llmqTypeChainLocks.dkgMiningWindowEnd + 1;
    // last possible block for last quorum period
    const auto& nLastDKGHeight = nQuorumStartHeight + Params().GetConsensus().llmqTypeChainLocks.dkgMiningWindowStart - 1;
    if(nHeight != nLastDKGHeight) {
        return false;
    }
    bool bHasCommitment = llmq::quorumBlockProcessor->HasMinedCommitment(pindexPrev->GetAncestor(nQuorumLastStartHeight)->GetBlockHash());
    const auto best_clsig = llmq::chainLocksHandler->GetBestChainLock();
    if (!best_clsig.IsNull()) {
        // if no mined commitment, we did not get a new quorum during this transition.
        if(!bHasCommitment) {
            return true;
        }
        // if there is a mined commitment make sure the CLSIG is from the period of blocks where its gauranteed to use the new quorum
        if(!(best_clsig.nHeight >= nQuorumLastMiningEnd && best_clsig.nHeight <= nLastDKGHeight)) {
            LogPrint(BCLog::CHAINLOCKS, "%s -- CLSIG (%s) height must be between nQuorumLastMiningEnd (%d) and nLastDKGHeight (%d) but found %d\n", __func__, best_clsig.ToString(), nQuorumLastMiningEnd, nLastDKGHeight, best_clsig.nHeight);
            return false;
        }
        // Return the latest known chainlock
        bestCL = best_clsig;
        return true;
    } else {
        const size_t& threshold = Params().GetConsensus().llmqTypeChainLocks.signingActiveQuorumCount / 2 + 1;
        // ensure we have atleast enough quorums to sign a chainlock
        const auto quorums_scanned = llmq::quorumManager->ScanQuorums(pindexPrev, threshold);
        // at this point we have enough quorums, and a recent commitment yet still no chainlock so return false so one can get fetched by peers or forced to push through by miners if actually no finality exists for this transition
        if (bHasCommitment && quorums_scanned.size() >= threshold) {
            return false;
        }
    }
    return true;
}

std::string CCbTxCLSIG::ToString() const
{
    return strprintf("CCbTxCLSIG(nVersion=%d, cl=%s)", static_cast<uint16_t>(nVersion), cl.ToString());
}
