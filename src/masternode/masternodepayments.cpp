// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/activemasternode.h>
#include <governance/governanceclasses.h>
#include <masternode/masternodepayments.h>
#include <masternode/masternodesync.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <spork.h>
#include <validation.h>

#include <consensus/pq_migration_config.h>
#include <consensus/merkle.h>
#include <evo/deterministicmns.h>
#include <evo/specialtx.h>
#include <string>

CMasternodePayments mnpayments;

bool HasValidatedSuperblockPayments(const CBlock& block, const CBlockIndex& index)
{
    if (!(index.nStatus & BLOCK_GOVERNANCE_VALIDATED) ||
        (index.nStatus & BLOCK_FAILED_MASK) ||
        !CSuperblock::IsValidBlockHeight(index.nHeight) ||
        index.phashBlock == nullptr || index.pprev == nullptr ||
        block.vtx.empty() || block.GetHash() != index.GetBlockHash() ||
        block.hashPrevBlock != index.pprev->GetBlockHash()) {
        return false;
    }
    // Block copies retain fChecked. Recompute the commitment instead of
    // trusting that cache when reusing a prior payment decision.
    bool mutated{false};
    const uint256 merkle_root{BlockMerkleRoot(block, &mutated)};
    return !mutated && merkle_root == block.hashMerkleRoot;
}

CAmount GetMinerPayment(MasternodePaymentStatus status,
                        const CAmount& blockReward, const CAmount& fees)
{
    assert(status == MasternodePaymentStatus::PAYEE ||
           status == MasternodePaymentStatus::PQ_NO_PAYEE);
    return (blockReward + 3) / 4 +
           (status == MasternodePaymentStatus::PQ_NO_PAYEE ? fees : fees / 2);
}

CAmount GetBlockPaymentValueLimit(MasternodePaymentStatus status,
                                 const CAmount& blockReward,
                                 const CAmount& fees,
                                 const CAmount& mnSeniority,
                                 const CAmount& mnFloorDiff)
{
    assert(status != MasternodePaymentStatus::UNAVAILABLE);
    // No operator exists to earn the missing share or its extra issuance.
    // The same reduced base also applies beneath superblock budget limits.
    if (status == MasternodePaymentStatus::PQ_NO_PAYEE) {
        return GetMinerPayment(status, blockReward, fees);
    }
    return blockReward + fees + mnSeniority + mnFloorDiff;
}

void CheckAndWriteBudget(const CAmount& nSuperblockPayment, const CAmount& nPaymentLimit, const CAmount& nGovernanceBudgetUp, const CBlockIndex* pindex) {
    CAmount nGovernanceBudgetDown = (nPaymentLimit * CSuperblock::SHIFT_DOWN) / CSuperblock::SHIFT;
    if (nGovernanceBudgetDown < CSuperblock::SUPERBLOCK_BUDGET_MIN) {
        nGovernanceBudgetDown = CSuperblock::SUPERBLOCK_BUDGET_MIN;
    }
    CAmount nPaymentsLimitUp   = (nPaymentLimit * CSuperblock::SHIFT_HALF_UP)   / CSuperblock::SHIFT;
    CAmount nPaymentsLimitDown = (nPaymentLimit * CSuperblock::SHIFT_HALF_DOWN) / CSuperblock::SHIFT;

    CAmount nAdjustment = nPaymentLimit;
    if(nSuperblockPayment > 0 && nSuperblockPayment <= nPaymentsLimitDown) {
        nAdjustment = nGovernanceBudgetDown;
    } else if(nSuperblockPayment >= nPaymentsLimitUp) {
        nAdjustment = nGovernanceBudgetUp;
    }
    governance->m_sb->WriteCache(pindex->GetBlockHash(), nAdjustment);
    if(nAdjustment != nPaymentLimit)
        LogPrint(BCLog::GOBJECT, "%s -- Adjusting SB limit to %lld (from %lld) for block %s\n", __func__, nAdjustment, nPaymentLimit, pindex->GetBlockHash().GetHex());
}
/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Syscoin some blocks are superblocks, which output much higher amounts of coins
*   - Other blocks are lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, const CBlockIndex* pindex, const CAmount &blockReward, std::string& strErrorRet, bool fJustCheck, bool check_superblock, bool* exact_superblock_validation, const std::vector<bool>* matched_outputs, bool* governance_state_available)
{
    if (exact_superblock_validation != nullptr) {
        *exact_superblock_validation = false;
    }
    if (governance_state_available != nullptr) {
        *governance_state_available = true;
    }
    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
    const int nBlockHeight = pindex->nHeight;
    strErrorRet = "";
    
    LogPrint(BCLog::MNPAYMENTS, "block.vtx[0]->GetValueOut() %lld <= blockReward %lld\n", block.vtx[0]->GetValueOut(), blockReward);
    if (!CSuperblock::IsValidBlockHeight(nBlockHeight)) {
        // can't possibly be a superblock, so lets just check for block reward limits
        if (!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, only regular blocks are allowed at this height",
                            nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        return isBlockRewardValueMet;
    }
    if(nBlockHeight < Params().GetConsensus().DIP0003Height) {
        return true;
    }
    const CAmount nSuperblockPayment = block.vtx[0]->GetValueOut() - blockReward;
    int sbCycle = Params().GetConsensus().SuperBlockCycle(nBlockHeight);
    int nLastSuperblock = nBlockHeight - sbCycle;
    const CBlockIndex* nLastSBIndex = pindex->GetAncestor(nLastSuperblock);
    const CAmount nPaymentLimit = CSuperblock::GetPaymentsLimit(nLastSBIndex);
    // Initial thresholds
    CAmount nGovernanceBudgetUp   = (nPaymentLimit * CSuperblock::SHIFT_UP)   / CSuperblock::SHIFT;
    if (nGovernanceBudgetUp > CSuperblock::SUPERBLOCK_BUDGET_MAX) {
        nGovernanceBudgetUp = CSuperblock::SUPERBLOCK_BUDGET_MAX;
    }
    
    const CAmount nSuperblockMaxValue =  blockReward + nGovernanceBudgetUp;

    bool isSuperblockMaxValueMet = block.vtx[0]->GetValueOut() <= nSuperblockMaxValue;
    LogPrint(BCLog::GOBJECT, "block.vtx[0]->GetValueOut() %lld <= nSuperblockMaxValue %lld (nGovernanceBudgetUp %lld) nSuperblockPayment %lld\n", block.vtx[0]->GetValueOut(), nSuperblockMaxValue, nGovernanceBudgetUp, nSuperblockPayment);

    // bail out in case superblock limits were exceeded
    if (!isSuperblockMaxValueMet) {
        strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded superblock max value",
                        nBlockHeight, block.vtx[0]->GetValueOut(), nSuperblockMaxValue);
        return false;
    }

    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MNPAYMENTS, "%s -- WARNING: Not enough data, checked superblock max bounds only\n", __func__);
        // not enough data for full checks but at least we know that the superblock limits were honored.
        // We rely on the network to have followed the correct chain in this case
        // follow longest chain as IsValid() doesn't get to validate nSuperblockPayment via the superblock
        if(!fJustCheck)
            CheckAndWriteBudget(nSuperblockPayment, nPaymentLimit, nGovernanceBudgetUp, pindex);
        return true;
    }

    // we are synced and possibly on a superblock now

    if (!AreSuperblocksEnabled()) {
        if (exact_superblock_validation != nullptr) {
            *exact_superblock_validation = true;
        }
        // should NOT allow superblocks at all, when superblocks are disabled
        // revert to block reward limits in this case
        LogPrint(BCLog::GOBJECT, "%s -- Superblocks are disabled, no superblocks allowed\n", __func__);
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, superblocks are disabled",
                            nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        return isBlockRewardValueMet;
    }
    // Off-chain votes can change after this exact block was connected. Keep
    // its verified payment decision, while still enforcing the limits above
    // and rebuilding the branch's adaptive budget after a disconnect.
    if (!check_superblock || HasValidatedSuperblockPayments(block, *pindex)) {
        if(!fJustCheck)
            CheckAndWriteBudget(nSuperblockPayment, nPaymentLimit, nGovernanceBudgetUp, pindex);
        return true;
    }
    const SuperblockTriggerState trigger_state{
        CSuperblockManager::GetSuperblockTriggerState(
            nBlockHeight, pindex->pprev)};
    if (trigger_state == SuperblockTriggerState::UNAVAILABLE) {
        if (governance_state_available != nullptr) {
            *governance_state_available = false;
        }
        strErrorRet = strprintf(
            "governance state is unavailable for parent of height %d",
            nBlockHeight);
        return false;
    }
    if (exact_superblock_validation != nullptr) {
        *exact_superblock_validation = true;
    }
    if (trigger_state == SuperblockTriggerState::NOT_TRIGGERED) {
        // we are on a valid superblock height but a superblock was not triggered
        // revert to block reward limits in this case
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, no triggered superblock detected",
                             nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        else if(!fJustCheck) {
            CheckAndWriteBudget(nSuperblockPayment, nPaymentLimit, nGovernanceBudgetUp, pindex);
        }
        return isBlockRewardValueMet;
    }
    // this actually also checks for correct payees and not only amount
    if (!CSuperblockManager::IsValidSuperblock(
            *block.vtx[0], nBlockHeight, blockReward,
            nGovernanceBudgetUp, matched_outputs, pindex->pprev)) {
        // triggered but invalid? that's weird
        LogPrintf("%s -- ERROR: Invalid superblock detected at height %d: %s", __func__, nBlockHeight, block.vtx[0]->ToString()); /* Continued */
        // should NOT allow invalid superblocks, when superblocks are enabled
        strErrorRet = strprintf("invalid superblock detected at height %d", nBlockHeight);
        return false;
    }
    // only store new limit if there was some governance
    if(!fJustCheck)
        CheckAndWriteBudget(nSuperblockPayment, nPaymentLimit, nGovernanceBudgetUp, pindex);
    // we got a valid superblock
    return true;
}

bool IsBlockPayeeValid(CChain& activeChain, const CTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount &fees, CAmount& nMNSeniorityRet, CAmount& nMNFloorDiffRet, std::vector<bool>* matched_outputs, MasternodePaymentStatus* payment_status)
{
    if (payment_status) *payment_status = MasternodePaymentStatus::LEGACY_NO_PAYEE;

    // we are still using budgets, but we have no data about them anymore,
    // we can only check masternode payments

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        // NOTE: old budget system is disabled since 12.1 and we should never enter this branch
        // anymore when sync is finished (on mainnet). We have no old budget data but these blocks
        // have tons of confirmations and can be safely accepted without payee verification
        LogPrint(BCLog::GOBJECT, "%s -- WARNING: Client synced but old budget system is disabled, accepting any payee\n", __func__);
        return true;
    }
    const CAmount nHalfFee = fees / 2;

    // Check for correct masternode payment
    MasternodePaymentStatus status;
    const bool valid{CMasternodePayments::IsTransactionValid(
        activeChain, txNew, nBlockHeight, blockReward, nHalfFee,
        nMNSeniorityRet, nMNFloorDiffRet, status, matched_outputs)};
    if (payment_status) *payment_status = status;
    if (valid) {
        LogPrint(BCLog::MNPAYMENTS, "%s -- Valid masternode payment at height %d\n", __func__, nBlockHeight);
        return true;
    }
    LogPrintf("%s -- ERROR: Invalid masternode payment detected at height %d\n", __func__, nBlockHeight); /* Continued */
    return false;
}

bool FillBlockPayments(CChain& activeChain, CMutableTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount &fees, std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& voutSuperblockPaymentsRet)
{
    // only create superblocks if spork is enabled AND if superblock is actually triggered
    // (height should be validated inside)
    if (AreSuperblocksEnabled() &&
        CSuperblock::IsValidBlockHeight(nBlockHeight)) {
        const CBlockIndex* expected_tip{activeChain.Tip()};
        const auto trigger_state{
            CSuperblockManager::GetSuperblockTriggerState(
                nBlockHeight, expected_tip)};
        if (trigger_state == SuperblockTriggerState::UNAVAILABLE) {
            LogPrintf("%s -- governance state unavailable at height %d\n",
                      __func__, nBlockHeight);
            return false;
        }
        if (trigger_state == SuperblockTriggerState::TRIGGERED) {
            LogPrint(BCLog::GOBJECT, "%s -- triggered superblock creation at height %d\n", __func__, nBlockHeight);
            if (!CSuperblockManager::GetSuperblockPayments(
                    nBlockHeight, voutSuperblockPaymentsRet,
                    expected_tip)) {
                return false;
            }
        }
    }

    const CAmount nHalfFee = fees / 2;
    const auto payment_status{CMasternodePayments::GetMasternodeTxOuts(
        activeChain, nBlockHeight, blockReward, voutMasternodePaymentsRet,
        nHalfFee)};
    if (payment_status == MasternodePaymentStatus::UNAVAILABLE) {
        return false;
    }
    if (payment_status == MasternodePaymentStatus::LEGACY_NO_PAYEE) {
        LogPrint(BCLog::MNPAYMENTS, "%s -- no masternode to pay (MN list probably empty)\n", __func__);
        return true;
    }
    // A verified empty PQ set leaves its subsidy allocation unminted while
    // giving the miner all fees. Governance payments must still be appended.
    txNew.vout[0].nValue =
        payment_status == MasternodePaymentStatus::PQ_NO_PAYEE ||
                !voutMasternodePaymentsRet.empty()
            ? GetMinerPayment(payment_status, blockReward, fees)
            : blockReward + nHalfFee;
    // mn is paid 75% of block reward plus any seniority
    txNew.vout.insert(txNew.vout.end(), voutMasternodePaymentsRet.begin(), voutMasternodePaymentsRet.end());
    // superblock governance amount is added as extra
    txNew.vout.insert(txNew.vout.end(), voutSuperblockPaymentsRet.begin(), voutSuperblockPaymentsRet.end());
    std::string voutMasternodeStr;
    for (const auto& txout : voutMasternodePaymentsRet) {
        if (!voutMasternodeStr.empty())
            voutMasternodeStr += ",";
        voutMasternodeStr += txout.ToString();
    }

    LogPrint(BCLog::MNPAYMENTS, "%s -- nBlockHeight %d blockReward %lld voutMasternodePaymentsRet \"%s\"\n", __func__,
                            nBlockHeight, blockReward, voutMasternodeStr);
    return true;
}

/**
*   GetMasternodeTxOuts
*
*   Get masternode payment tx outputs
*/

MasternodePaymentStatus CMasternodePayments::GetMasternodeTxOuts(CChain& activeChain, int nBlockHeight, const CAmount &blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, const CAmount &nHalfFee)
{
    // make sure it's not filled yet
    voutMasternodePaymentsRet.clear();
    CAmount nMNSeniorityRet;
    CAmount nMNFloorDiffRet;
    int nCollateralHeight;
    const auto status{GetBlockTxOuts(
        activeChain, nBlockHeight, blockReward, voutMasternodePaymentsRet,
        nHalfFee, nMNSeniorityRet, nMNFloorDiffRet, nCollateralHeight)};
    if (status != MasternodePaymentStatus::PAYEE) {
        if (status == MasternodePaymentStatus::UNAVAILABLE) {
            LogPrintf("CMasternodePayments::%s -- payment state unavailable\n", __func__);
        } else {
            LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::%s -- no eligible payee\n", __func__);
        }
        return status;
    }

    for (const auto& txout : voutMasternodePaymentsRet) {
        CTxDestination dest;
        ExtractDestination(txout.scriptPubKey, dest);

        LogPrintf("CMasternodePayments::%s -- Masternode payment %lld to %s\n", __func__, txout.nValue, EncodeDestination(dest));
    }

    return status;
}
CAmount GetBlockMNSubsidy(const CAmount &nBlockReward, unsigned int nHeight, const Consensus::Params& consensusParams, unsigned int nStartHeight, CAmount& nMNSeniorityRet, CAmount& nMNFloorDiffRet)
{
    // MN takes 75% of the subsidy
    CAmount nSubsidy = nBlockReward*0.75;
    
    // ensure that if subsidy is less than min amount then stick to min for long term MN full node/chainlock incentive
    const CAmount &nMinMN = consensusParams.nMinMNSubsidySats;
    if(nSubsidy < nMinMN) {
        nMNFloorDiffRet = nMinMN-nSubsidy;
        nSubsidy = nMinMN;
    }
    if (nHeight > 0 && nStartHeight > 0) {
        const double fSubsidyAdjustmentPercentage = consensusParams.Seniority(nHeight, nStartHeight);
        if(fSubsidyAdjustmentPercentage > 0){
            nMNSeniorityRet = nSubsidy*fSubsidyAdjustmentPercentage;
            nSubsidy += nMNSeniorityRet;
        }
    }
    return nSubsidy;
}
MasternodePaymentStatus CMasternodePayments::GetBlockTxOuts(CChain& activeChain, int nBlockHeight, const CAmount &blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, const CAmount &nHalfFee, CAmount& nMNSeniorityRet, CAmount &nMNFloorDiffRet, int& nCollateralHeightRet)
{
    voutMasternodePaymentsRet.clear();
    nMNSeniorityRet = 0;
    nMNFloorDiffRet = 0;
    nCollateralHeightRet = 0;
    const auto eligibility{Consensus::CheckPQPaymentEligibility(
        Params().GetConsensus(), nBlockHeight)};
    if (eligibility ==
        Consensus::PQPaymentEligibilityResult::INVALID_CONFIGURATION) {
        return MasternodePaymentStatus::UNAVAILABLE;
    }
    const bool pq_payments{
        eligibility == Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED};
    const auto unavailable{pq_payments
        ? MasternodePaymentStatus::UNAVAILABLE
        : MasternodePaymentStatus::LEGACY_NO_PAYEE};
    CDeterministicMNCPtr dmnPayee;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex = activeChain[nBlockHeight - 1];
        if(!pindex)
            return unavailable;
        try {
            if (!deterministicMNManager->GetMNPayeeForBlock(pindex, dmnPayee)) {
                return unavailable;
            }
        } catch (const std::exception& e) {
            if (!pq_payments) throw;
            LogPrintf("%s -- payment state unavailable at height %d: %s\n",
                      __func__, nBlockHeight, e.what());
            return MasternodePaymentStatus::UNAVAILABLE;
        }
    }
    if (!dmnPayee) {
        return pq_payments ? MasternodePaymentStatus::PQ_NO_PAYEE
                           : MasternodePaymentStatus::LEGACY_NO_PAYEE;
    }
    nCollateralHeightRet = dmnPayee->pdmnState->nCollateralHeight;
    CAmount masternodeReward = GetBlockMNSubsidy(blockReward, nBlockHeight, Params().GetConsensus(), nCollateralHeightRet, nMNSeniorityRet, nMNFloorDiffRet) + nHalfFee;

    CAmount operatorReward = 0;
    if (dmnPayee->nOperatorReward != 0 && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
        // This calculation might eventually turn out to result in 0 even if an operator reward percentage is given.
        // This will however only happen in a few years when the block rewards drops very low.
        operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
        masternodeReward -= operatorReward;
    }

    if (masternodeReward > 0) {
        voutMasternodePaymentsRet.emplace_back(masternodeReward, dmnPayee->pdmnState->scriptPayout);
    }
    if (operatorReward > 0) {
        voutMasternodePaymentsRet.emplace_back(operatorReward, dmnPayee->pdmnState->scriptOperatorPayout);
    }

    return MasternodePaymentStatus::PAYEE;
}

bool CMasternodePayments::IsTransactionValid(CChain& activeChain, const CTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount& nHalfFee, CAmount& nMNSeniorityRet, CAmount &nMNFloorDiffRet, MasternodePaymentStatus& payment_status, std::vector<bool>* matched_outputs)
{
    payment_status = MasternodePaymentStatus::LEGACY_NO_PAYEE;
    if (matched_outputs) {
        matched_outputs->assign(txNew.vout.size(), false);
    }
    // PQ eligibility starts at its own activation even when a regtest profile
    // delays the historical DIP3 payment-enforcement height.
    if (Consensus::CheckPQPaymentEligibility(Params().GetConsensus(), nBlockHeight) ==
            Consensus::PQPaymentEligibilityResult::LEGACY &&
        (!deterministicMNManager || !deterministicMNManager->IsDIP3Enforced(nBlockHeight))) {
        return true;
    }
    if (!deterministicMNManager) {
        payment_status = MasternodePaymentStatus::UNAVAILABLE;
        return false;
    }

    std::vector<CTxOut> voutMasternodePayments;
    int nCollateralHeight;
    payment_status = GetBlockTxOuts(
        activeChain, nBlockHeight, blockReward, voutMasternodePayments,
        nHalfFee, nMNSeniorityRet, nMNFloorDiffRet, nCollateralHeight);
    if (payment_status == MasternodePaymentStatus::UNAVAILABLE) {
        return false;
    }
    if (payment_status != MasternodePaymentStatus::PAYEE) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::%s -- no eligible payee at height %d\n", __func__, nBlockHeight);
        return true;
    }

    std::vector<bool> outputs_used(txNew.vout.size());
    for (const auto& txout : voutMasternodePayments) {
        bool found = false;
        for (size_t i = 0; i < txNew.vout.size(); ++i) {
            if (!outputs_used[i] && txout == txNew.vout[i]) {
                outputs_used[i] = true;
                found = true;
                break;
            }
        }
        if (!found) {
            CTxDestination dest;
            if (!ExtractDestination(txout.scriptPubKey, dest))
                assert(false);
            LogPrintf("CMasternodePayments::%s -- ERROR failed to find expected payee %s in block at height %s\n", __func__, EncodeDestination(dest), nBlockHeight);
            return false;
        }
    }
    if (matched_outputs) {
        *matched_outputs = std::move(outputs_used);
    }
    return true;
}
