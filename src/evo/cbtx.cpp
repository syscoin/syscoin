#include <evo/cbtx.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <llmq/quorums_signing.h>
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
    // last height before new DKG starts
    const auto& nQuorumEndHeight = pindex->nHeight + (pindex->nHeight % Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    const auto& nQuorumStartHeight = pindex->nHeight - (pindex->nHeight % Params().GetConsensus().llmqTypeChainLocks.dkgInterval);
    // last possible block before new quorum can be mined
    const auto& nLastDKGHeight = nQuorumEndHeight + Params().GetConsensus().llmqTypeChainLocks.dkgMiningWindowStart - 1;
    if ((pindex->nHeight % nLastDKGHeight) != 0) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-mining-height");
    }

    CCbTxCLSIG cbTx;
    if (!GetTxPayload(*block.vtx[0], cbTx)) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-payload");
    }
    if (cbTx.nVersion != CCbTxCLSIG::CURRENT_VERSION) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-bad-version");
    }
    // if there was no mined commitment this DKG interval we can skip and assume quorums stayed the same (no new quorum)
    if (!llmq::quorumBlockProcessor->HasMinedCommitment(pindex->GetAncestor(nQuorumStartHeight)->GetBlockHash())) {
        // shouldn't happen on regtest
        if(fRegTest) {
            assert(false);
        }
        // if there is no mined commitment, the CLSIG should be null as otherwise it would not belong to this DKG interval
        return cbTx.cl.IsNull();
    }
    const uint256 minedCommitmentHash = llmq::quorumBlockProcessor->GetMinedCommitmentBlockHash(pindex->GetAncestor(nQuorumStartHeight)->GetBlockHash());
    if(minedCommitmentHash.IsNull()) {
        LogPrint(BCLog::CHAINLOCKS, "CChainLocksHandler::%s -- CLSIG (%s) mined commitment doesn't exist yet, not allowed)\n", __func__, cbTx.cl.ToString());
        return false;
    }
    const auto pindexCommitment = chainman.m_blockman.LookupBlockIndex(minedCommitmentHash);
    if(cbTx.cl.nHeight <= pindexCommitment->nHeight) {
        LogPrint(BCLog::CHAINLOCKS, "CChainLocksHandler::%s -- CLSIG (%s) height must be higher than the mined commitment for this DKG interval (%d)\n", __func__, cbTx.cl.ToString(), pindexCommitment->nHeight);
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-bad-height");
    }

    const auto latestChainLock = llmq::chainLocksHandler->GetBestChainLock();
    // if chainlock exists and it is part of this DKG interval validate that the CLSIG provided is valid and also part of this DKG interval
    if (!latestChainLock.IsNull() && latestChainLock.nHeight >= pindexCommitment->nHeight) {
        // Enforce non-null chainlocks if a valid local chainlock exists in this DKG interval
        if(cbTx.cl.IsNull()) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-missing-clsig");
        }
        LogPrintf("CheckCbTxBestChainlock check cl match latestChainLock %s cbTx.cl %s fJustCheck %d\n", latestChainLock.ToString(), cbTx.cl.ToString(), fJustCheck);
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
                LogPrint(BCLog::CHAINLOCKS, "CChainLocksHandler::%s -- invalid CLSIG (%s)\n", __func__, cbTx.cl.ToString());
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-invalid-sig");
            }
        }  
    }
    // If no valid local chainlock, verify the chainlock in the block against the active chain
    else if (!cbTx.cl.IsNull()) {
        LogPrintf("CheckCbTxBestChainlock no local CL found, check new one %s fJustCheck %d\n", cbTx.cl.ToString(), fJustCheck);
        const auto chainLockBlockIndex = chainman.m_blockman.LookupBlockIndex(cbTx.cl.blockHash);
        if (!chainLockBlockIndex || !chainman.ActiveChain().Contains(chainLockBlockIndex) || !chainLockBlockIndex->IsValid(BLOCK_VALID_SCRIPTS)) {
            return state.Invalid(BlockValidationResult::BLOCK_RECENT_CONSENSUS_CHANGE, "clsig-bad-block");
        }
        if(chainLockBlockIndex->nHeight != cbTx.cl.nHeight) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-height-mismatch");
        }
        if (!llmq::chainLocksHandler->VerifyAggregatedChainLock(cbTx.cl, chainLockBlockIndex, ::SerializeHash(cbTx.cl))) {
            LogPrint(BCLog::CHAINLOCKS, "CChainLocksHandler::%s -- invalid CLSIG (%s)\n", __func__, cbTx.cl.ToString());
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "cbtx-clsig-invalid-sig");
        }
    }

    return true;
}

bool CalcCbTxBestChainlock(const CBlockIndex* pindexPrev, llmq::CChainLockSig& bestCL)
{
    const auto best_clsig = llmq::chainLocksHandler->GetBestChainLock();
    if (!best_clsig.IsNull()) {
        // cannot have a CLSIG if there is no mined commitment for that DKG interval (must be an old CLSIG)
        if(!llmq::quorumBlockProcessor->HasMinedCommitment(pindexPrev->GetAncestor(pindexPrev->nHeight - (pindexPrev->nHeight % Params().GetConsensus().llmqTypeChainLocks.dkgInterval))->GetBlockHash())) {
            // shouldn't happen in tests
            if(fRegTest) {
                assert(false);
            }
            return false;
        }
        // Return the latest known chainlock
        bestCL = best_clsig;
        return true;
    }
    return false;
}

std::string CCbTxCLSIG::ToString() const
{
    return strprintf("CCbTxCLSIG(nVersion=%d, cl=%s)", static_cast<uint16_t>(nVersion), cl.ToString());
}
