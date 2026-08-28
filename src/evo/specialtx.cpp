// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <validation.h>

#include <evo/deterministicmns.h>
#include <evo/specialtx.h>
#include <util/time.h>
#include <llmq/quorums_commitment.h>
#include <llmq/quorums_blockprocessor.h>
#include <logging.h>
#include <governance/governance.h>

class CCoinsViewCache;

bool CheckSpecialTx(node::BlockManager &blockman, const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context)
{

    try {
        switch (tx.nVersion) {
        case SYSCOIN_TX_VERSION_MN_REGISTER:
            return CheckProRegTx(tx, pindexPrev, state, view, fJustCheck, check_sigs);
        case SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE:
            return CheckProUpServTx(tx, pindexPrev, state, fJustCheck,
                                    check_sigs, validation_context);
        case SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR:
            return CheckProUpRegTx(tx, pindexPrev, state, view, fJustCheck, check_sigs);
        case SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE:
            return CheckProUpRevTx(tx, pindexPrev, state, fJustCheck,
                                   check_sigs, validation_context);
        case SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY: {
            if (!deterministicMNManager) {
                // SYSCOIN: Missing node-local auxiliary state is not a
                // transaction consensus failure.
                return state.Error("failed-pq-registry-unavailable");
            }
            // A false check_sigs value is an optimization hint, not consensus
            // authority. Only named deferred-validation paths may skip here.
            const bool verify_authorization =
                validation_context !=
                    SpecialTxValidationContext::PQ_REGISTRY_PRECHECK &&
                (check_sigs || validation_context ==
                                   SpecialTxValidationContext::NORMAL);
            return deterministicMNManager->CheckPQTransaction(
                tx, pindexPrev, state, fJustCheck, verify_authorization);
        }
        default:
            return true;
        }
    } catch (const std::exception& e) {
        LogPrintf("%s -- failed: %s\n", __func__, e.what());
        return FormatSyscoinErrorMessage(state, "failed-check-special-tx", fJustCheck);
    }

    return FormatSyscoinErrorMessage(state, "bad-tx-type-check", fJustCheck);
}


bool ProcessSpecialTxsInBlock(ChainstateManager &chainman, const CBlock& block, const CBlockIndex* pindex, BlockValidationState& state, CDeterministicMNListNEVMAddressDiff &diff, CCoinsViewCache& view, bool fJustCheck, bool check_sigs, bool ibd, SpecialTxValidationContext validation_context)
{
    try {
        static SteadyClock::duration nTimeLoop{};
        static SteadyClock::duration nTimeQuorum{};

        auto nTime1 = SystemClock::now();
        llmq::CFinalCommitmentTxPayload qcTx;
        for (const auto& ptr_tx : block.vtx) {
            TxValidationState txstate;
            // The registry below owns the consensus authorization and state
            // transition for tx86 and post-PQ provider revocations. Its first
            // pass remains structural so an SLH signature is verified once.
            const bool registry_owned{
                ptr_tx->nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY ||
                ptr_tx->nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE};
            const auto tx_validation_context{
                registry_owned
                    ? SpecialTxValidationContext::PQ_REGISTRY_PRECHECK
                    : validation_context};
            if (!CheckSpecialTx(chainman.m_blockman, *ptr_tx, pindex->pprev,
                                txstate, view, false, check_sigs,
                                tx_validation_context)) {
                // SYSCOIN: Preserve local auxiliary-state failures so a
                // valid block is never cached as consensus-invalid.
                if (txstate.IsError()) {
                    return state.Error(txstate.GetRejectReason());
                }
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, txstate.GetRejectReason());
            }
        }

        auto nTime2 = SystemClock::now(); nTimeLoop += nTime2 - nTime1;
        LogPrint(BCLog::BENCHMARK, "        - Loop: %.2fms [%.2fs]\n",  Ticks<MillisecondsDouble>(nTime2 - nTime1), Ticks<SecondsDouble>(nTimeLoop));

        if (!llmq::quorumBlockProcessor->ProcessBlock(block, pindex, state, qcTx, fJustCheck, check_sigs)) {
            // pass the state returned by the function above
            return false;
        }

        auto nTime3 = SystemClock::now(); nTimeQuorum += nTime3 - nTime2;
        LogPrint(BCLog::BENCHMARK, "        - quorumBlockProcessor: %.2fms [%.2fs]\n",  Ticks<MillisecondsDouble>(nTime3 - nTime2), Ticks<SecondsDouble>(nTimeQuorum));

        if (!deterministicMNManager || !deterministicMNManager->ProcessBlock(
                block, pindex, state, view, qcTx, diff, fJustCheck, ibd)) {
            // pass the state returned by the function above
            return false;
        }
    } catch (const std::exception&) {
        return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-procspectxsinblock");
    }

    return true;
}

bool UndoSpecialTxsInBlock(const CBlock& block, const CBlockIndex* pindex, CDeterministicMNListNEVMAddressDiff& diffNEVM, bool bUpdateSpecialTxState, bool bReplay)
{
    try {
        if(bUpdateSpecialTxState) {
            // The CChain tip still names pindex while the deterministic and
            // quorum snapshots below are rolled back. Close branch-bound
            // governance reads before either snapshot can diverge from it.
            if (governance) governance->ObserveChainTip(nullptr);
            if (!deterministicMNManager || !deterministicMNManager->UndoBlock(pindex, diffNEVM)) {
                return false;
            }
            if (!llmq::quorumBlockProcessor->UndoBlock(block, pindex)) {
                return false;
            }
            // replay doesn't connect block which writes governance SB to cache again
            if(!bReplay) {
                if (!governance->UndoBlock(pindex)) {
                    return false;
                }
            }
        }

    } catch (const std::exception& e) {
        return error(strprintf("%s -- failed: %s\n", __func__, e.what()).c_str());
    }

    return true;
}

uint256 CalcTxInputsHash(const CTransaction& tx)
{
    CHashWriter hw(SER_GETHASH, CLIENT_VERSION);
    for (const auto& in : tx.vin) {
        hw << in.prevout;
    }
    return hw.GetHash();
}
