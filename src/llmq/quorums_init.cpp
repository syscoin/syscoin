// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_init.h>

#include <chain.h>
#include <chainparams.h>
#include <common/args.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_chainlocks.h>
#include <llmq/pq_chainlock_test_fixture.h>
#include <llmq/pq_quorum_overlay.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <logging.h>
#include <validation.h>

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace llmq
{

void InitLLMQSystem(CConnman& connman,
                    PeerManager& peerman,
                    ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const PQHistoryAuthState initialization_state{
        MakePQChainLockFinalityStoreConfig(chainman.GetConsensus())
            ? PQHistoryAuthState::UNINITIALIZED
            : PQHistoryAuthState::READY};
    if (!chainman.PublishPQHistoryAuthState(
            initialization_state)) {
        throw std::runtime_error(
            "cannot recreate PQ finality after public IBD completed");
    }

    pq::QuorumSnapshotLookup snapshot_lookup{
        [](const CBlockIndex& index)
            -> std::optional<pq::QuorumSnapshotState> {
            if (!deterministicMNManager) return std::nullopt;

            pq::QuorumSnapshotState state;
            state.deterministic_mns =
                deterministicMNManager->GetListForBlock(&index);

            pq::PQRegistrySnapshot registry_snapshot;
            std::string error;
            if (!deterministicMNManager->GetPQRegistrySnapshot(
                    &index, registry_snapshot, error)) {
                LogPrint(BCLog::CHAINLOCKS,
                         "PQ quorum snapshot unavailable at height=%d block=%s: %s\n",
                         index.nHeight, index.GetBlockHash().ToString(), error);
                return std::nullopt;
            }
            state.operator_key_states =
                std::move(registry_snapshot.operator_states);
            return state;
        }};

    if (gArgs.IsArgSet("-pqchainlocktestfixture")) {
        if (chainman.GetParams().GetChainType() != ChainType::REGTEST ||
            !chainman.GetParams().MineBlocksOnDemand()) {
            throw std::runtime_error(
                "-pqchainlocktestfixture is restricted to mine-on-demand "
                "regression-test chains");
        }
        const fs::path fixture_path{
            gArgs.GetPathArg("-pqchainlocktestfixture")};
        if (fixture_path.empty() || !fixture_path.is_absolute()) {
            throw std::runtime_error(
                "-pqchainlocktestfixture requires an absolute path");
        }
        const auto build_config{
            MakePQQuorumBuildConfig(chainman.GetConsensus())};
        if (!build_config) {
            throw std::runtime_error(
                "-pqchainlocktestfixture requires a complete PQ deployment");
        }
        std::string error;
        auto fixture_lookup{pq::test::LoadQuorumSnapshotFixture(
            fixture_path, chainman.GetConsensus().hashGenesisBlock,
            *build_config, chainman, error)};
        if (!fixture_lookup) {
            throw std::runtime_error(
                "invalid PQ ChainLock test fixture: " + error);
        }
        snapshot_lookup = std::move(*fixture_lookup);
        LogPrintf("Loaded branch-bound PQ ChainLock regtest fixture\n");
    }

    // SYSCOIN: This processor is retained only to reconstruct the deterministic
    // masternode state committed by the mandatory migration anchor. It has no
    // live P2P or mining path.
    quorumBlockProcessor = new CQuorumBlockProcessor();
    chainLocksHandler = new CChainLocksHandler(connman, peerman, chainman);
    // SYSCOIN: Frozen SLH rosters need only deterministic share-relay
    // connectivity; there is no DKG or threshold-key lifecycle.
    const int32_t initial_predecessor_height{
        chainman.GetConsensus().nPQChainLockAnchorHeight};
    pqQuorumConnectionOverlay = new CPQQuorumConnectionOverlay(
        connman, chainman.GetConsensus().hashGenesisBlock,
        MakePQQuorumBuildConfig(chainman.GetConsensus()),
        [initial_predecessor_height]() -> std::optional<int32_t> {
            const auto best{chainLocksHandler
                                ? chainLocksHandler->GetBestChainLock()
                                : nullptr};
            return best ? best->statement.height
                        : initial_predecessor_height;
        });
    chainLocksHandler->SetQuorumSnapshotLookup(std::move(snapshot_lookup));
}

void DestroyLLMQSystem()
{
    delete pqQuorumConnectionOverlay;
    pqQuorumConnectionOverlay = nullptr;
    delete chainLocksHandler;
    chainLocksHandler = nullptr;
    delete quorumBlockProcessor;
    quorumBlockProcessor = nullptr;
}

void StartLLMQSystem()
{
    if (chainLocksHandler) {
        chainLocksHandler->Start();
    }
}

void StopLLMQSystem()
{
    if (pqQuorumConnectionOverlay) {
        pqQuorumConnectionOverlay->Clear();
    }
    if (chainLocksHandler) {
        chainLocksHandler->Stop();
    }
}

} // namespace llmq
