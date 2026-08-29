// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate.h>

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/params.h>
#include <consensus/pq_migration_config.h> // SYSCOIN: validate the height-only PQ deployment.
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <sync.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
// SYSCOIN
#include <services/nevmconsensus.h>
#include <services/assetconsensus.h>
#include <evo/evodb.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_chainlocks.h> // SYSCOIN: startup handoff finality provenance.
#include <llmq/quorums_init.h>
#include <governance/governance.h>
#include <netfulfilledman.h>
#include <spork.h>
#include <masternode/masternodemeta.h>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <limits>
#include <memory>
#include <vector>

namespace node {
namespace {

// SYSCOIN: A loaded coins database is usable only when its branch-local
// deterministic-MN, rollback, probation, and PQ-registry state is intact.
bool VerifyActivePQState(const Chainstate& chainstate)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    const auto& consensus = chainstate.m_chainman.GetConsensus();
    llmq::pq::PQRegistryConfig pq_config;
    const auto pq_deployment =
        llmq::pq::GetPQRegistryConfig(consensus, pq_config);
    if (pq_deployment ==
        llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
        return false;
    }
    if (Consensus::CheckPQActivationConfiguration(consensus) ==
        Consensus::PQActivationResult::INVALID_CONFIGURATION) {
        return false;
    }
    const CBlockIndex* tip = chainstate.m_chain.Tip();
    llmq::pq::PQPaymentProbationStateView probation_state;
    if (tip != nullptr && tip->nHeight >= consensus.DIP0003Height &&
        (deterministicMNManager == nullptr ||
         !deterministicMNManager->VerifyPersistedSnapshot(tip) ||
         !deterministicMNManager->VerifyInverseJournalTipSeal(tip) ||
         !deterministicMNManager->GetPaymentProbationStateView(
             tip, probation_state))) {
        // The inverse DB is intentionally versioned and not backfilled from a
        // bounded snapshot window. Fresh sync or reindex inductively publishes
        // each predecessor seal. Startup also resolves the exact probation
        // root referenced by the tip; later physical LevelDB damage remains
        // fail-closed at point of use.
        return false;
    }
    return pq_deployment != llmq::pq::PQRegistryDeploymentResult::VALID ||
           tip == nullptr ||
           (deterministicMNManager != nullptr &&
            deterministicMNManager->VerifyPersistedPQRegistrySnapshot(tip));
}

} // namespace
// Complete initialization of chainstates after the initial call has been made
// to ChainstateManager::InitializeChainstate().
static ChainstateLoadResult CompleteChainstateInitialization(
    ChainstateManager& chainman,
    const CacheSizes& cache_sizes,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    auto& pblocktree{chainman.m_blockman.m_block_tree_db};
    // new BlockTreeDB tries to delete the existing file, which
    // fails if it's still open from the previous loop. Close it first:
    pblocktree.reset();
    pblocktree = std::make_unique<BlockTreeDB>(DBParams{
        .path = chainman.m_options.datadir / "blocks" / "index",
        .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = options.reindex,
        .options = chainman.m_options.block_tree_db});

    if (options.reindex) {
        pblocktree->WriteReindexing(true);
        //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
        if (options.prune) {
            chainman.m_blockman.CleanupBlockRevFiles();
        }
    }

    bool disk_reindexing{false};
    pblocktree->ReadReindexing(disk_reindexing);
    const bool effective_reindex_geth{options.fReindexGeth || disk_reindexing};
    // SYSCOIN Keep nevmminttx lifetime aligned with UTXO chainstate rebuilds only.
    // Reconstructible NEVM/Geth auxiliary DBs may still follow effective_reindex_geth.
    // Empty-coins recovery below also clears nevmminttx when needed.
    const bool wipe_mint_replay{options.reindex || options.reindex_chainstate};
    if (disk_reindexing && !options.fReindexGeth) {
        fReindexGeth = true;
        LogPrintf("Continuing reindex from persisted marker; forcing NEVM/LLMQ database reinitialization.\n");
    }

    // SYSCOIN: Recreate fork-owned deterministic-MN, governance, and PQ
    // finality state alongside the Bitcoin block-tree lifecycle.
    LogPrintf("Creating legacy quorum replay state and PQ finality...\n");
    llmq::DestroyLLMQSystem();
    auto evoDmnDbParams = DBParams{
        .path = chainman.m_options.datadir / "evodb_dmn",
        .cache_bytes = static_cast<size_t>(cache_sizes.evo_dmn_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = effective_reindex_geth,
        .options = chainman.m_options.block_tree_db};
    deterministicMNManager.reset();
    deterministicMNManager.reset(new CDeterministicMNManager(evoDmnDbParams));
    governance.reset();
    governance.reset(new CGovernanceManager(chainman));
    sporkManager.reset();
    sporkManager.reset(new CSporkManager());
    netfulfilledman.reset();
    netfulfilledman.reset(new CNetFulfilledRequestManager());
    mmetaman.reset();
    mmetaman.reset(new CMasternodeMetaMan());
    // SYSCOIN: Initialize the fork-owned finality stack against this rebuilt chainstate.
    llmq::InitLLMQSystem(*options.connman, *options.peerman, chainman);
    pnevmtxrootsdb.reset();
    pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(DBParams{
        .path = chainman.m_options.datadir / "nevmtxroots",
        .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = effective_reindex_geth,
        .options = chainman.m_options.block_tree_db});
    pnevmtxmintdb.reset();
    pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
        .path = chainman.m_options.datadir / "nevmminttx",
        .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = wipe_mint_replay,
        .options = chainman.m_options.block_tree_db});
    pblockindexdb.reset();
    pblockindexdb = std::make_unique<CBlockIndexDB>(DBParams{
        .path = chainman.m_options.datadir / "dbblockindex",
        .cache_bytes = static_cast<size_t>(cache_sizes.evo_dmn_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = effective_reindex_geth,
        .options = chainman.m_options.block_tree_db});
    pnevmdatadb.reset();
    pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
        .path = chainman.m_options.datadir / "nevmdata",
        .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = effective_reindex_geth,
        .options = chainman.m_options.coins_db});
    pnevmdatablobdb.reset();  
    // PoDA blob data cannot be deleted from disk on reindex because chain on disk does not have PoDA information to recreate it
    pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
        .path = chainman.m_options.datadir / "nevmblobdata",
        .cache_bytes = static_cast<size_t>(cache_sizes.evo_poda_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = false,
        .options = chainman.m_options.coins_db});  
    if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // LoadBlockIndex will load m_have_pruned if we've ever removed a
    // block file from disk.
    // Note that it also sets fReindex global based on the disk flag!
    // From here on, fReindex and options.reindex values may be different!
    if (!chainman.LoadBlockIndex()) {
        if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};
        return {ChainstateLoadStatus::FAILURE, _("Error loading block database")};
    }

    if (!chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashGenesisBlock)) {
        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no genesis block found. Wrong datadir for network?")};
    }

    // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
    // in the past, but is now trying to run unpruned.
    if (chainman.m_blockman.m_have_pruned && !options.prune) {
        return {ChainstateLoadStatus::FAILURE, _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain")};
    }

    // At this point blocktree args are consistent with what's on disk.
    // If we're not mid-reindex (based on disk + args), add a genesis block on disk
    // (otherwise we use the one already on disk).
    // This is called again in ImportBlocks after the reindex completes.
    if (!fReindex && !chainman.ActiveChainstate().LoadGenesisBlock()) {
        return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
    }

    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.reindex || options.reindex_chainstate || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    assert(chainman.m_total_coinstip_cache > 0);
    assert(chainman.m_total_coinsdb_cache > 0);

    // Conservative value which is arbitrarily chosen, as it will ultimately be changed
    // by a call to `chainman.MaybeRebalanceCaches()`. We just need to make sure
    // that the sum of the two caches (40%) does not exceed the allowable amount
    // during this temporary initialization state.
    double init_cache_fraction = 0.2;

    // At this point we're either in reindex or we've loaded a useful
    // block tree into BlockIndex()!
    // SYSCOIN
    bool coinsViewEmpty = false;
    std::vector<Chainstate*> loaded_chainstates;
    auto chainstates{chainman.GetAll()};
    Chainstate* const active_chainstate{&chainman.ActiveChainstate()};
    // SYSCOIN BEGIN: Publish the recovered tip with durable finality authority.
    const auto publish_startup_tip = [&](const CBlockIndex* recovered_tip)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return deterministicMNManager == nullptr ||
               deterministicMNManager->UpdatedBlockTipForStartup(
                   recovered_tip,
                   [&](const uint256& hash)
                       EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
                       return chainman.m_blockman.LookupBlockIndex(hash);
                   },
                   llmq::chainLocksHandler
                       ? llmq::chainLocksHandler
                             ->GetDurableFinalityTargetForStartup()
                       : std::nullopt);
    };
    // SYSCOIN END: Publish the recovered tip with durable finality authority.
    // SYSCOIN: The active recovery head is the ancestry authority for shared
    // journal-bound stores. Load it before an AssumeUTXO background state.
    std::stable_partition(
        chainstates.begin(), chainstates.end(),
        [active_chainstate](const Chainstate* chainstate) {
            return chainstate == active_chainstate;
        });
    for (Chainstate* chainstate : chainstates) {
        LogPrintf("Initializing chainstate %s\n", chainstate->ToString());

        chainstate->InitCoinsDB(
            /*cache_size_bytes=*/chainman.m_total_coinsdb_cache * init_cache_fraction,
            /*in_memory=*/options.coins_db_in_memory,
            /*should_wipe=*/options.reindex || options.reindex_chainstate);

        // SYSCOIN BEGIN: Persist replay quarantine before opaque legacy state
        // can be reconstructed by this BLS-free binary.
        if (chainstate == active_chainstate) {
            const bool coins_db_empty{
                chainstate->CoinsDB().GetBestBlock().IsNull() &&
                chainstate->CoinsDB().GetHeadBlocks().empty()};
            const bool force_historical_replay{
                options.reindex || options.reindex_chainstate ||
                disk_reindexing || chainman.IsSnapshotActive()};
            bilingual_str handoff_error;
            if (!chainman.PreparePQActivationHandoff(
                    force_historical_replay, coins_db_empty,
                    handoff_error)) {
                return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB,
                        handoff_error};
            }
        }
        // SYSCOIN END: Persist replay quarantine before legacy replay.

        if (options.coins_error_cb) {
            chainstate->CoinsErrorCatcher().AddReadErrCallback(options.coins_error_cb);
        }

        // Refuse to load unsupported database format.
        // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (chainstate->CoinsDB().NeedsUpgrade()) {
            return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Unsupported chainstate database format found. "
                                                                     "Please restart with -reindex-chainstate. This will "
                                                                     "rebuild the chainstate database.")};
        }

        // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (!chainstate->ReplayBlocks()) {
            return {ChainstateLoadStatus::FAILURE, _("Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate.")};
        }

        // The on-disk coinsdb is now in a good state, create the cache
        chainstate->InitCoinsCache(chainman.m_total_coinstip_cache * init_cache_fraction);
        assert(chainstate->CanFlushToDisk());

        if (!is_coinsview_empty(chainstate)) {
            // LoadChainTip initializes the chain based on CoinsTip()'s best block
            if (!chainstate->LoadChainTip()) {
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
            assert(chainstate->m_chain.Tip() != nullptr);
            // SYSCOIN BEGIN: Establish or verify the exact local A-1 handoff
            // before any public service can observe startup readiness.
            if (chainstate == active_chainstate) {
                bilingual_str handoff_error;
                if (!chainman.FinalizePQActivationHandoff(
                        chainstate->m_chain.Tip(), handoff_error)) {
                    return {
                        ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB,
                        handoff_error};
                }
            }
            // SYSCOIN END: Verify the local PQ activation handoff.
            if (chainstate == active_chainstate &&
                !publish_startup_tip(chainstate->m_chain.Tip())) {
                return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB,
                        _("Auxiliary-history GC authorization is not compatible with the recovered active chain")};
            }
            loaded_chainstates.push_back(chainstate);
        }
        // SYSCOIN
        else {
            coinsViewEmpty = true;
        }
    }

    // SYSCOIN: Publish the loaded active tip before opening any journal-bound
    // auxiliary store. A pending GC intent is authenticated against the
    // active chain, which may be the snapshot chainstate loaded after its IBD
    // counterpart. Verify every loaded recovery chainstate only after that
    // active-chain identity is available.
    if (!coinsViewEmpty && !loaded_chainstates.empty()) {
        const CBlockIndex* active_tip{active_chainstate->m_chain.Tip()};
        if (active_tip == nullptr) {
            return {ChainstateLoadStatus::FAILURE,
                    _("Error initializing active chain tip")};
        }
        if (!publish_startup_tip(active_tip)) {
            return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB,
                    _("Auxiliary-history GC authorization is not compatible with the recovered active chain")};
        }
        for (const Chainstate* chainstate : loaded_chainstates) {
            // SYSCOIN: Treat an auxiliary-state mismatch as an incompatible
            // database, not a recoverable tip-selection error; reindexing is
            // required to reconstruct the branch-bound records.
            if (!VerifyActivePQState(*chainstate)) {
                return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB,
                        _("Post-quantum deterministic masternode state, rollback-journal tip seal, payment probation state, or PQ key registry is missing or invalid. Reindex with the matching Syscoin release; existing pre-journal datadirs cannot be backfilled from the bounded snapshot window.")};
            }
        }
        if (deterministicMNManager) {
            deterministicMNManager->UpdatedBlockTip(active_tip);
        }
    }

    if (!options.reindex) {
        auto chainstates{chainman.GetAll()};
        if (std::any_of(chainstates.begin(), chainstates.end(),
                        [](const Chainstate* cs) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return cs->NeedsRedownload(); })) {
            return {ChainstateLoadStatus::FAILURE, strprintf(_("Witness data for blocks after height %d requires validation. Please restart with -reindex."),
                                                             chainman.GetConsensus().SegwitHeight)};
        };
    }
    // if coinsview is empty we clear all SYS db's overriding anything we did before
    // SYSCOIN: An empty UTXO view cannot reuse branch-bound deterministic-MN
    // or PQ finality databases from the prior chainstate.
    if(coinsViewEmpty && !effective_reindex_geth) {
        LogPrintf("coinsViewEmpty recreating LLMQ and NEVM databases\n");
        llmq::DestroyLLMQSystem();
        auto evoDmnDbParams = DBParams{
            .path = chainman.m_options.datadir / "evodb_dmn",
            .cache_bytes = static_cast<size_t>(cache_sizes.evo_dmn_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = coinsViewEmpty,
            .options = chainman.m_options.block_tree_db};
        deterministicMNManager.reset();
        deterministicMNManager.reset(new CDeterministicMNManager(evoDmnDbParams));
        governance.reset();
        governance.reset(new CGovernanceManager(chainman));
        sporkManager.reset();
        sporkManager.reset(new CSporkManager());
        netfulfilledman.reset();
        netfulfilledman.reset(new CNetFulfilledRequestManager());
        mmetaman.reset();
        mmetaman.reset(new CMasternodeMetaMan());
        // SYSCOIN: Rebind fork-owned finality after empty-coins recovery.
        llmq::InitLLMQSystem(*options.connman, *options.peerman, chainman);
        pnevmtxrootsdb.reset();
        pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(DBParams{
            .path = chainman.m_options.datadir / "nevmtxroots",
            .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = coinsViewEmpty,
            .options = chainman.m_options.block_tree_db});
        pnevmtxmintdb.reset();
        pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
            .path = chainman.m_options.datadir / "nevmminttx",
            .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = coinsViewEmpty,
            .options = chainman.m_options.block_tree_db});
        pblockindexdb.reset();
        pblockindexdb = std::make_unique<CBlockIndexDB>(DBParams{
            .path = chainman.m_options.datadir / "dbblockindex",
            .cache_bytes = static_cast<size_t>(cache_sizes.evo_dmn_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = coinsViewEmpty,
            .options = chainman.m_options.block_tree_db});
        pnevmdatadb.reset();
        pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
            .path = chainman.m_options.datadir / "nevmdata",
            .cache_bytes = static_cast<size_t>(cache_sizes.evo_poda_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = coinsViewEmpty,
            .options = chainman.m_options.coins_db});
        pnevmdatablobdb.reset();  
        // PoDA blob data cannot be deleted from disk on reindex because chain on disk does not have PoDA information to recreate it
        pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
            .path = chainman.m_options.datadir / "nevmblobdata",
            .cache_bytes = static_cast<size_t>(cache_sizes.evo_poda_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = false,
            .options = chainman.m_options.coins_db});  
    } else if (coinsViewEmpty) {
        // SYSCOIN Continued reindex already reinitialized reconstructible NEVM DBs above
        // via effective_reindex_geth, which skips the block above. nevmminttx still
        // must clear whenever the UTXO set is empty so replay state matches chainstate.
        LogPrintf("coinsViewEmpty recreating NEVM mint-replay database\n");
        pnevmtxmintdb.reset();
        pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
            .path = chainman.m_options.datadir / "nevmminttx",
            .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
            .memory_only = options.block_tree_db_in_memory,
            .wipe_data = true,
            .options = chainman.m_options.block_tree_db});
    }

    // Now that chainstates are loaded and we're able to flush to
    // disk, rebalance the coins caches to desired levels based
    // on the condition of each chainstate.
    chainman.MaybeRebalanceCaches();

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult LoadChainstate(ChainstateManager& chainman, const CacheSizes& cache_sizes,
                                    const ChainstateLoadOptions& options)
{
    if (!chainman.AssumedValidBlock().IsNull()) {
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", chainman.AssumedValidBlock().GetHex());
    } else {
        LogPrintf("Validating signatures for all blocks.\n");
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", chainman.MinimumChainWork().GetHex());
    if (chainman.MinimumChainWork() < UintToArith256(chainman.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainman.GetConsensus().nMinimumChainWork.GetHex());
    }
    if (chainman.m_blockman.GetPruneTarget() == BlockManager::PRUNE_TARGET_MANUAL) {
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
    } else if (chainman.m_blockman.GetPruneTarget()) {
        LogPrintf("Prune configured to target %u MiB on disk for block and undo files.\n", chainman.m_blockman.GetPruneTarget() / 1024 / 1024);
    }

    LOCK(cs_main);

    ChainstateLoadOptions effective_options{options};
    if (!effective_options.reindex && !effective_options.block_tree_db_in_memory) {
        auto& pblocktree{chainman.m_blockman.m_block_tree_db};
        pblocktree.reset();
        pblocktree = std::make_unique<BlockTreeDB>(DBParams{
            .path = chainman.m_options.datadir / "blocks" / "index",
            .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
            .memory_only = false,
            .wipe_data = false,
            .options = chainman.m_options.block_tree_db});
        bool persisted_reindex{false};
        pblocktree->ReadReindexing(persisted_reindex);
        pblocktree.reset();
        if (persisted_reindex) {
            LogPrintf("Persisted reindex marker found before chainstate load; starting full block-file reindex.\n");
            effective_options.reindex = true;
            effective_options.fReindexGeth = true;
            fReindex = true;
            fReindexGeth = true;
        }
    }

    chainman.m_total_coinstip_cache = cache_sizes.coins;
    chainman.m_total_coinsdb_cache = cache_sizes.coins_db;

    // Load the fully validated chainstate.
    chainman.InitializeChainstate(effective_options.mempool);

    // Load a chain created from a UTXO snapshot, if any exist.
    bool has_snapshot = chainman.DetectSnapshotChainstate();

    if (has_snapshot && (effective_options.reindex || effective_options.reindex_chainstate)) {
        LogPrintf("[snapshot] deleting snapshot chainstate due to reindexing\n");
        if (!chainman.DeleteSnapshotChainstate()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Couldn't remove snapshot chainstate.")};
        }
    }

    auto [init_status, init_error] = CompleteChainstateInitialization(chainman, cache_sizes, effective_options);
    if (init_status != ChainstateLoadStatus::SUCCESS) {
        return {init_status, init_error};
    }

    // If a snapshot chainstate was fully validated by a background chainstate during
    // the last run, detect it here and clean up the now-unneeded background
    // chainstate.
    //
    // Why is this cleanup done here (on subsequent restart) and not just when the
    // snapshot is actually validated? Because this entails unusual
    // filesystem operations to move leveldb data directories around, and that seems
    // too risky to do in the middle of normal runtime.
    auto snapshot_completion = chainman.MaybeCompleteSnapshotValidation();

    if (snapshot_completion == SnapshotCompletionResult::SKIPPED) {
        // do nothing; expected case
    } else if (snapshot_completion == SnapshotCompletionResult::SUCCESS) {
        LogPrintf("[snapshot] cleaning up unneeded background chainstate, then reinitializing\n");
        if (!chainman.ValidatedSnapshotCleanup()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Background chainstate cleanup failed unexpectedly.")};
        }

        // Because ValidatedSnapshotCleanup() has torn down chainstates with
        // ChainstateManager::ResetChainstates(), reinitialize them here without
        // duplicating the blockindex work above.
        assert(chainman.GetAll().empty());
        assert(!chainman.IsSnapshotActive());
        assert(!chainman.IsSnapshotValidated());

        chainman.InitializeChainstate(effective_options.mempool);

        // A reload of the block index is required to recompute setBlockIndexCandidates
        // for the fully validated chainstate.
        chainman.ActiveChainstate().ClearBlockIndexCandidates();

        auto [init_status, init_error] = CompleteChainstateInitialization(chainman, cache_sizes, effective_options);
        if (init_status != ChainstateLoadStatus::SUCCESS) {
            return {init_status, init_error};
        }
    } else {
        return {ChainstateLoadStatus::FAILURE, _(
           "UTXO snapshot failed to validate. "
           "Restart to resume normal initial block download, or try loading a different snapshot.")};
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, const ChainstateLoadOptions& options)
{
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.reindex || options.reindex_chainstate || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    for (Chainstate* chainstate : chainman.GetAll()) {
        if (!is_coinsview_empty(chainstate)) {
            const CBlockIndex* tip = chainstate->m_chain.Tip();
            if (tip && tip->nTime > GetTime() + MAX_FUTURE_BLOCK_TIME) {
                return {ChainstateLoadStatus::FAILURE, _("The block database contains a block which appears to be from the future. "
                                                         "This may be due to your computer's date and time being set incorrectly. "
                                                         "Only rebuild the block database if you are sure that your computer's date and time are correct")};
            }

            // SYSCOIN: Mint replay markers live outside VerifyDB's temporary coins view.
            // Level-4 reconnect sees already-applied markers as mint-exists. Cap at 3;
            // fail closed if the operator required full verification.
            int check_level = options.check_level;
            if (check_level >= 4) {
                if (options.require_full_verification) {
                    return {ChainstateLoadStatus::FAILURE,
                            _("Check level 4 is unavailable with NEVM mint replay state")};
                }
                LogPrintf("Clamping VerifyDB check level from %d to 3 because NEVM mint "
                          "replay markers are external to the temporary view\n",
                          check_level);
                check_level = 3;
            }

            VerifyDBResult result = CVerifyDB(chainman.GetNotifications()).VerifyDB(
                *chainstate, chainman.GetConsensus(), chainstate->CoinsDB(),
                check_level,
                options.check_blocks);
            switch (result) {
            case VerifyDBResult::SUCCESS:
            case VerifyDBResult::SKIPPED_MISSING_BLOCKS:
                break;
            case VerifyDBResult::INTERRUPTED:
                return {ChainstateLoadStatus::INTERRUPTED, _("Block verification was interrupted")};
            case VerifyDBResult::CORRUPTED_BLOCK_DB:
                return {ChainstateLoadStatus::FAILURE, _("Corrupted block database detected")};
            case VerifyDBResult::SKIPPED_L3_CHECKS:
                if (options.require_full_verification) {
                    return {ChainstateLoadStatus::FAILURE_INSUFFICIENT_DBCACHE, _("Insufficient dbcache for block verification")};
                }
                break;
            } // no default case, so the compiler can warn about missing cases
        }
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}
} // namespace node
