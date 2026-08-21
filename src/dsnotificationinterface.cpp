// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <dsnotificationinterface.h>
#include <governance/governance.h>
#include <masternode/masternodesync.h>
#include <validation.h>

#include <evo/deterministicmns.h>
#include <evo/mnauth.h>

#include <llmq/quorums_chainlocks.h>
#include <llmq/pq_quorum_overlay.h>
#include <shutdown.h>
#include <net_processing.h>
void CDSNotificationInterface::InitializeCurrentBlockTip(ChainstateManager& chainman)
{
    const CBlockIndex* tip{nullptr};
    bool initial_block_download{false};
    {
        LOCK(cs_main);
        tip = chainman.ActiveChain().Tip();
        if (deterministicMNManager) {
            deterministicMNManager->UpdatedBlockTip(tip);
        }
        initial_block_download = chainman.IsInitialBlockDownload();
    }
    UpdatedBlockTip(
        tip, nullptr, chainman, initial_block_download);
}


void CDSNotificationInterface::NotifyHeaderTip(const CBlockIndex *pindexNew)
{
    if(llmq::chainLocksHandler)
        llmq::chainLocksHandler->NotifyHeaderTip(pindexNew);
    masternodeSync.NotifyHeaderTip(pindexNew);
}

void CDSNotificationInterface::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, ChainstateManager& chainman, bool fInitialDownload)
{
    if (pindexNew == pindexFork || ShutdownRequested()) // blocks were disconnected without any new ones
        return;

    masternodeSync.UpdatedBlockTip(pindexNew, chainman, fInitialDownload);

    // SYSCOIN: Keep the bounded frozen-roster relay overlay synchronized even
    // when entering IBD, which clears obsolete connection groups immediately.
    if (llmq::pqQuorumConnectionOverlay) {
        llmq::pqQuorumConnectionOverlay->UpdatedBlockTip(pindexNew,
                                                          fInitialDownload);
    }

    if (fInitialDownload)
        return;
    if(llmq::chainLocksHandler)
        llmq::chainLocksHandler->UpdatedBlockTip(pindexNew, fInitialDownload);
    CMNAuth::UpdatedBlockTip(pindexNew, connman);
    if (governance && governance->IsValid()) governance->UpdatedBlockTip(pindexNew, connman, peerman);
}

void CDSNotificationInterface::InitialBlockDownloadCompleted(
    const CBlockIndex* tip, ChainstateManager& chainman)
{
    if (tip == nullptr || ShutdownRequested()) return;
    masternodeSync.UpdatedBlockTip(tip, chainman,
                                  /*fInitialDownload=*/false);
    if (llmq::pqQuorumConnectionOverlay) {
        llmq::pqQuorumConnectionOverlay->UpdatedBlockTip(
            tip, /*initial_download=*/false);
    }
    if (llmq::chainLocksHandler) {
        llmq::chainLocksHandler->UpdatedBlockTip(
            tip, /*initial_download=*/false);
    }
    CMNAuth::UpdatedBlockTip(tip, connman);
    if (governance && governance->IsValid()) {
        governance->UpdatedBlockTip(tip, connman, peerman);
    }
}

void CDSNotificationInterface::NotifyMasternodeListChanged(
    bool, const CDeterministicMNList&, const CDeterministicMNListDiff&)
{
    if(ShutdownRequested())
        return;
    if(governance && governance->IsValid()) {
        governance->CheckAndRemove();
    }
}
