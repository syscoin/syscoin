// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/pq_migration.h> // SYSCOIN: pinned migration-anchor tests.
#include <consensus/validation.h>
#include <evo/pq_payment_probation_db.h> // SYSCOIN: multi-chainstate probation GC.
#include <kernel/disconnected_transactions.h>
#include <llmq/pq_chainlock_schedule.h> // SYSCOIN: payment-audit preseal coverage.
#include <llmq/quorums_chainlocks.h> // SYSCOIN: retained probation roots.
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <uint256.h>
#include <validation.h>
#include <validationinterface.h>

#include <tinyformat.h>

#include <array> // SYSCOIN: synthetic migration-anchor fixtures.
#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

// SYSCOIN: Test seam for branch-local compact payment-audit replay.
bool IsPaymentAuditHistoricalPresealCoverable(
    ChainstateManager& chainman,
    const CBlockIndex& carrier,
    const llmq::pq::ChainLockScheduleConfig& schedule);

BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

//! Basic tests for ChainstateManager.
//!
//! First create a legacy (IBD) chainstate, then create a snapshot chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    std::vector<Chainstate*> chainstates;

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);

    BOOST_CHECK(!manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    auto all = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all.begin(), all.end(), chainstates.begin(), chainstates.end());

    auto& active_chain = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain, &c1.m_chain);

    // Get to a valid assumeutxo tip (per chainparams);
    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    auto active_tip = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    auto exp_tip = c1.m_chain.Tip();
    BOOST_CHECK_EQUAL(active_tip, exp_tip);

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a snapshot-based chainstate.
    //
    const uint256 snapshot_blockhash = active_tip->GetBlockHash();
    Chainstate& c2 = WITH_LOCK(::cs_main, return manager.ActivateExistingSnapshot(snapshot_blockhash));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /* cache_size_bytes */ 1 << 23, /* in_memory */ true, /* should_wipe */ false);
    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        c2.CoinsTip().SetBestBlock(active_tip->GetBlockHash());
        c2.setBlockIndexCandidates.insert(manager.m_blockman.LookupBlockIndex(active_tip->GetBlockHash()));
        c2.LoadChainTip();
    }
    BlockValidationState _;
    BOOST_CHECK(c2.ActivateBestChain(_, nullptr));

    BOOST_CHECK_EQUAL(manager.SnapshotBlockhash().value(), snapshot_blockhash);
    BOOST_CHECK(manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    BOOST_CHECK_EQUAL(&c2, &manager.ActiveChainstate());
    BOOST_CHECK(&c1 != &manager.ActiveChainstate());
    auto all2 = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all2.begin(), all2.end(), chainstates.begin(), chainstates.end());

    auto& active_chain2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain2, &c2.m_chain);

    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 111);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return c1.m_chain.Height()), 110);

    auto active_tip2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    BOOST_CHECK_EQUAL(active_tip, active_tip2->pprev);
    BOOST_CHECK_EQUAL(active_tip, c1.m_chain.Tip());
    BOOST_CHECK_EQUAL(active_tip2, c2.m_chain.Tip());

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    SyncWithValidationInterfaceQueue();
}

// SYSCOIN: GC must retain roots referenced by every usable chainstate tip.
BOOST_FIXTURE_TEST_CASE(
    payment_probation_gc_retains_every_chainstate_tip,
    TestChain100Setup)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& background{chainman.ActiveChainstate()};

    mineBlocks(10);
    const CBlockIndex* snapshot_base{
        WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    BOOST_REQUIRE(snapshot_base != nullptr);
    Chainstate& snapshot{WITH_LOCK(
        ::cs_main,
        return chainman.ActivateExistingSnapshot(
            snapshot_base->GetBlockHash()))};
    snapshot.InitCoinsDB(/*cache_size_bytes=*/1 << 23,
                         /*in_memory=*/true,
                         /*should_wipe=*/false);
    {
        LOCK(::cs_main);
        snapshot.InitCoinsCache(1 << 23);
        snapshot.CoinsTip().SetBestBlock(snapshot_base->GetBlockHash());
        snapshot.setBlockIndexCandidates.insert(
            chainman.m_blockman.LookupBlockIndex(
                snapshot_base->GetBlockHash()));
        snapshot.LoadChainTip();
    }
    BlockValidationState activation_state;
    BOOST_REQUIRE(snapshot.ActivateBestChain(activation_state, nullptr));
    mineBlocks(1);

    const auto non_null_hash = [](uint8_t tag) {
        uint256 hash;
        hash.begin()[0] = tag;
        return hash;
    };
    const auto make_state = [&](uint32_t epoch, uint8_t tag) {
        llmq::pq::PQPaymentProbationState state;
        state.cursor.has_receipt = 1;
        state.cursor.receipt = {
            epoch, static_cast<int32_t>(1'000 + epoch),
            non_null_hash(tag)};
        state.entries.push_back(
            {non_null_hash(static_cast<uint8_t>(tag + 32)), 1, -1});
        return state;
    };
    llmq::pq::PQPaymentProbationManager probation_db{DBParams{
        .path = m_path_root / "probation_multichain_retention",
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    }};
    const auto commit = [&](const auto& state) {
        const auto hash{llmq::pq::GetPQPaymentProbationStateHash(state)};
        BOOST_REQUIRE(hash.has_value());
        BOOST_REQUIRE(probation_db.CommitState(
            state, *hash, /*fJustCheck=*/false));
        return *hash;
    };
    const uint256 background_root{commit(make_state(4, 1))};
    const uint256 snapshot_root{commit(make_state(5, 2))};
    const uint256 unreferenced_root{commit(make_state(5, 3))};

    std::vector<uint256> retained_roots;
    {
        LOCK(::cs_main);
        CBlockIndex* background_tip{background.m_chain.Tip()};
        CBlockIndex* snapshot_tip{snapshot.m_chain.Tip()};
        BOOST_REQUIRE(background_tip != nullptr);
        BOOST_REQUIRE(snapshot_tip != nullptr);
        BOOST_REQUIRE(background_tip != snapshot_tip);
        const uint256 saved_background_root{
            background_tip->pqPaymentProbationStateHash};
        const uint256 saved_snapshot_root{
            snapshot_tip->pqPaymentProbationStateHash};
        background_tip->pqPaymentProbationStateHash = background_root;
        snapshot_tip->pqPaymentProbationStateHash = snapshot_root;
        retained_roots =
            llmq::CollectChainstatePaymentProbationRoots(chainman);
        background_tip->pqPaymentProbationStateHash =
            saved_background_root;
        snapshot_tip->pqPaymentProbationStateHash = saved_snapshot_root;
    }

    BOOST_CHECK_EQUAL(retained_roots.size(), 2U);
    BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                          background_root) != retained_roots.end());
    BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                          snapshot_root) != retained_roots.end());
    BOOST_REQUIRE(probation_db.PruneStatesThroughEpoch(
        /*prune_through_epoch=*/5, retained_roots));

    llmq::pq::PQPaymentProbationState loaded;
    BOOST_CHECK(probation_db.GetState(background_root, loaded));
    BOOST_CHECK(probation_db.GetState(snapshot_root, loaded));
    BOOST_CHECK(!probation_db.GetState(unreferenced_root, loaded));

    SyncWithValidationInterfaceQueue();
}

//! Test rebalancing the caches associated with each chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebalance_caches, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;

    size_t max_cache = 10000;
    manager.m_total_coinsdb_cache = max_cache;
    manager.m_total_coinstip_cache = max_cache;

    std::vector<Chainstate*> chainstates;

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);
    uint256 snapshot_base_hash;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(c1.m_chain.Tip() != nullptr);
        CBlockIndex* snapshot_base = c1.m_chain[c1.m_chain.Height() / 2];
        BOOST_REQUIRE(snapshot_base != nullptr);
        BOOST_REQUIRE(snapshot_base->phashBlock != nullptr);
        snapshot_base_hash = *snapshot_base->phashBlock;
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, max_cache);
    BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, max_cache);
    SyncWithValidationInterfaceQueue();
    // Create a snapshot-based chainstate.
    //
    Chainstate* c2_ptr{nullptr};
    {
        LOCK(::cs_main);
        Chainstate& active_before = manager.ActiveChainstate();
        BOOST_REQUIRE(&active_before == &c1);
        c2_ptr = &manager.ActivateExistingSnapshot(snapshot_base_hash);
    }
    Chainstate& c2 = *c2_ptr;
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /* cache_size_bytes */ static_cast<size_t>(max_cache * 0.95), /* in_memory */ true, /* should_wipe */ false);

    // Reset IBD state so IsInitialBlockDownload() returns true and causes
    // MaybeRebalancesCaches() to prioritize the snapshot chainstate, giving it
    // more cache space than the snapshot chainstate. Calling ResetIbd() is
    // necessary because m_cached_finished_ibd is already latched to true before
    // the test starts due to the test setup. After ResetIbd() is called.
    // IsInitialBlockDownload will return true because at this point the active
    // chainstate has a null chain tip.
    static_cast<TestChainstateManager&>(manager).ResetIbd();

    {
        LOCK(::cs_main);
        // SYSCOIN: Keep snapshot coinstip cache at the expected rebalance target
        // so this test does not force a flush on a snapshot chainstate that has
        // not loaded a chain tip yet.
        c2.InitCoinsCache(static_cast<size_t>(max_cache * 0.95));
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_CLOSE(c1.m_coinstip_cache_size_bytes, max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(c1.m_coinsdb_cache_size_bytes, max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(c2.m_coinstip_cache_size_bytes, max_cache * 0.95, 1);
    BOOST_CHECK_CLOSE(c2.m_coinsdb_cache_size_bytes, max_cache * 0.95, 1);

    // SYSCOIN Ensure queued validationinterface callbacks drain before fixture teardown.
    // This avoids use-after-free races against chainstate structures.
    SyncWithValidationInterfaceQueue();
}

// SYSCOIN BEGIN: PQ migration and payment-audit chainstate-manager regressions.
// The exact migration anchor can arrive after a higher-work fork below
// the anchor height became active. That forbidden tip must not prevent the node
// from selecting the lower-work anchored branch for recovery.
BOOST_FIXTURE_TEST_CASE(pq_anchor_recovery_ignores_forbidden_tip_work,
                        TestChain100Setup)
{
    // SYSCOIN: BasicTestingSetup pins DIP3 at 550. Extend the already-checked
    // 100-block fixture here so the synthetic migration anchor is genuinely
    // post-DIP3 without depending on a brittle hard-coded 600-block tip hash.
    mineBlocks(500);
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int old_anchor_height = consensus.nPQLegacyAnchorHeight;
    const uint256 old_anchor_block = consensus.hashPQLegacyAnchorBlock;
    const uint256 old_anchor_state = consensus.hashPQLegacyMNState;
    const uint256 old_anchor_pq_state =
        consensus.hashPQLegacyPQRegistryState;
    struct RestoreAnchorParams {
        Consensus::Params& consensus;
        int height;
        uint256 block;
        uint256 state;
        uint256 pq_state;
        ~RestoreAnchorParams()
        {
            consensus.nPQLegacyAnchorHeight = height;
            consensus.hashPQLegacyAnchorBlock = block;
            consensus.hashPQLegacyMNState = state;
            consensus.hashPQLegacyPQRegistryState = pq_state;
        }
    } restore{consensus, old_anchor_height, old_anchor_block, old_anchor_state,
              old_anchor_pq_state};

    LOCK(::cs_main);
    constexpr int anchor_height{600};
    CBlockIndex* const original_tip = chainstate.m_chain.Tip();
    CBlockIndex* const anchor = chainstate.m_chain[anchor_height];
    BOOST_REQUIRE(original_tip != nullptr);
    BOOST_REQUIRE(anchor != nullptr);
    BOOST_REQUIRE(anchor->pprev != nullptr);

    consensus.nPQLegacyAnchorHeight = anchor_height;
    consensus.hashPQLegacyAnchorBlock = anchor->GetBlockHash();
    consensus.hashPQLegacyMNState = uint256::ONEV;
    consensus.hashPQLegacyPQRegistryState = uint256S("3");

    BOOST_REQUIRE(
        Consensus::CheckPQLegacyAnchorConfiguration(consensus) ==
        Consensus::PQLegacyAnchorResult::VALID);
    BOOST_REQUIRE_EQUAL(
        chainman.m_blockman.LookupBlockIndex(anchor->GetBlockHash()), anchor);
    BOOST_REQUIRE(Consensus::IsPQLegacyAnchorCompatible(
        consensus, original_tip, anchor));
    BOOST_REQUIRE(original_tip->IsValid(BLOCK_VALID_TREE));
    BOOST_REQUIRE(!(original_tip->nStatus &
                    (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)));

    uint256 fork_hash = GetRandHash();
    while (fork_hash == anchor->pprev->GetBlockHash()) fork_hash = GetRandHash();
    CBlockIndex forbidden_tip;
    forbidden_tip.phashBlock = &fork_hash;
    forbidden_tip.pprev = anchor->pprev->pprev;
    forbidden_tip.nHeight = anchor_height - 1;
    forbidden_tip.nChainWork = original_tip->nChainWork + 1;

    const auto original_candidates = chainstate.setBlockIndexCandidates;
    CBlockIndex* const original_best_header = chainman.m_best_header;
    chainstate.m_chain.SetTip(forbidden_tip);
    chainstate.setBlockIndexCandidates.clear();

    BOOST_CHECK(!Consensus::IsPQLegacyAnchorCompatible(
        consensus, chainstate.m_chain.Tip(), anchor));
    BOOST_CHECK(node::CBlockIndexWorkComparator()(anchor, &forbidden_tip));
    BOOST_CHECK(chainman.EnforcePQLegacyAnchorBranches());
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(anchor), 1U);

    chainstate.setBlockIndexCandidates.clear();
    chainstate.TryAddBlockIndexCandidate(anchor);
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(anchor), 1U);
    chainstate.PruneBlockIndexCandidates();
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(anchor), 1U);

    chainstate.m_chain.SetTip(*original_tip);
    chainstate.setBlockIndexCandidates = original_candidates;
    chainman.m_best_header = original_best_header;
}

// A missing BTCC receipt certificate is a data dependency, not block
// invalidity. Its first-seen carrier must nevertheless leave the work selector
// so an equally worked, fully verifiable sibling can activate.
BOOST_FIXTURE_TEST_CASE(btcc_pending_candidate_yields_and_requeues_exactly,
                        TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    WAIT_LOCK(::cs_main, main_lock);
    CBlockIndex* const active_tip{chainstate.m_chain.Tip()};
    BOOST_REQUIRE(active_tip != nullptr);

    uint256 pending_hash{GetRandHash()};
    uint256 sibling_hash{GetRandHash()};
    while (sibling_hash == pending_hash) sibling_hash = GetRandHash();
    CBlockIndex pending;
    pending.phashBlock = &pending_hash;
    pending.pprev = active_tip;
    pending.nHeight = active_tip->nHeight + 1;
    pending.nChainWork = active_tip->nChainWork + 1;
    pending.nTx = 1;
    pending.nChainTx = active_tip->nChainTx + 1;
    pending.nSequenceId = 1;
    pending.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;

    CBlockIndex sibling;
    sibling.phashBlock = &sibling_hash;
    sibling.pprev = active_tip;
    sibling.nHeight = pending.nHeight;
    sibling.nChainWork = pending.nChainWork;
    sibling.nTx = 1;
    sibling.nChainTx = pending.nChainTx;
    sibling.nSequenceId = 2;
    sibling.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;

    const auto original_candidates{chainstate.setBlockIndexCandidates};
    struct RestoreCandidates {
        Chainstate& chainstate;
        CBlockIndex* tip;
        const std::set<CBlockIndex*, node::CBlockIndexWorkComparator>
            candidates;
        ~RestoreCandidates()
        {
            chainstate.ClearBlockIndexCandidates();
            chainstate.m_chain.SetTip(*tip);
            chainstate.setBlockIndexCandidates = candidates;
        }
    } restore{chainstate, active_tip, original_candidates};

    chainstate.setBlockIndexCandidates.clear();
    chainstate.setBlockIndexCandidates.insert(active_tip);
    chainstate.setBlockIndexCandidates.insert(&pending);
    chainstate.setBlockIndexCandidates.insert(&sibling);
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(pending));

    uint256 logical_id{GetRandHash()};
    while (logical_id.IsNull()) logical_id = GetRandHash();
    BOOST_REQUIRE(
        chainstate.DeferBTCCReceiptCandidates(logical_id, pending));
    BOOST_CHECK(
        chainstate.DeferBTCCReceiptCandidates(logical_id, pending));
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(&pending), 0U);
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(pending));
    BOOST_CHECK(chainstate.HasDeferredBTCCReceiptCandidates(logical_id));
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(sibling));

    // Even generic candidate reconstruction cannot bypass the quarantine at
    // FindMostWorkChain's selection boundary.
    chainstate.setBlockIndexCandidates.insert(&pending);
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(sibling));
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(&pending), 0U);

    // A descendant learned after the carrier was quarantined must inherit the
    // dependency before it can displace or disconnect the active sibling.
    uint256 descendant_hash{GetRandHash()};
    CBlockIndex descendant;
    descendant.phashBlock = &descendant_hash;
    descendant.pprev = &pending;
    descendant.nHeight = pending.nHeight + 1;
    descendant.nChainWork = pending.nChainWork + 1;
    descendant.nTx = 1;
    descendant.nChainTx = pending.nChainTx + 1;
    descendant.nSequenceId = 3;
    descendant.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&descendant);
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(descendant));
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&descendant), 0U);
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(sibling));

    // Quarantine state scales with live fork tips, not every block on a long
    // descendant chain. Exact release reconstructs ordinary ancestry
    // membership from that single maximal tip.
    std::array<uint256, 32> descendant_hashes;
    std::array<CBlockIndex, 32> descendants;
    CBlockIndex* descendant_tip{&descendant};
    for (size_t i{0}; i < descendants.size(); ++i) {
        descendant_hashes[i] = GetRandHash();
        CBlockIndex& next{descendants[i]};
        next.phashBlock = &descendant_hashes[i];
        next.pprev = descendant_tip;
        next.nHeight = descendant_tip->nHeight + 1;
        next.nChainWork = descendant_tip->nChainWork + 1;
        next.nTx = 1;
        next.nChainTx = descendant_tip->nChainTx + 1;
        next.nSequenceId = 4 + static_cast<int32_t>(i);
        next.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        chainstate.TryAddBlockIndexCandidate(&next);
        descendant_tip = &next;
    }
    uint256 rebuilt_hash{GetRandHash()};
    CBlockIndex rebuilt_descendant;
    rebuilt_descendant.phashBlock = &rebuilt_hash;
    rebuilt_descendant.pprev = descendant_tip;
    rebuilt_descendant.nHeight = descendant_tip->nHeight + 1;
    rebuilt_descendant.nChainWork = descendant_tip->nChainWork + 1;
    rebuilt_descendant.nTx = 1;
    rebuilt_descendant.nChainTx = descendant_tip->nChainTx + 1;
    rebuilt_descendant.nSequenceId = 500;
    rebuilt_descendant.nStatus =
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.setBlockIndexCandidates.insert(&rebuilt_descendant);
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(sibling));
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&rebuilt_descendant), 0U);
    descendant_tip = &rebuilt_descendant;

    const auto compact_dependency{
        chainstate.GetBestDeferredBTCCReceiptCandidate()};
    BOOST_REQUIRE(compact_dependency.has_value());
    BOOST_CHECK_EQUAL(compact_dependency->logical_id, logical_id);
    BOOST_CHECK_EQUAL(compact_dependency->best_candidate, descendant_tip);
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(pending));
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(descendant));
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(*descendant_tip));

    // Multiple mined receipt IDs remain bounded by their block candidates,
    // while the single request lane deterministically selects the dependency
    // with the highest-work tip.
    uint256 higher_hash{GetRandHash()};
    CBlockIndex higher_pending;
    higher_pending.phashBlock = &higher_hash;
    higher_pending.pprev = active_tip;
    higher_pending.nHeight = pending.nHeight;
    higher_pending.nChainWork = descendant_tip->nChainWork + 1;
    higher_pending.nTx = 1;
    higher_pending.nChainTx = pending.nChainTx;
    higher_pending.nSequenceId = 1000;
    higher_pending.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&higher_pending);
    uint256 higher_logical_id{GetRandHash()};
    while (higher_logical_id.IsNull() ||
           higher_logical_id == logical_id) {
        higher_logical_id = GetRandHash();
    }
    BOOST_REQUIRE(chainstate.DeferBTCCReceiptCandidates(
        higher_logical_id, higher_pending));
    const auto best_dependency{
        chainstate.GetBestDeferredBTCCReceiptCandidate()};
    BOOST_REQUIRE(best_dependency.has_value());
    BOOST_CHECK_EQUAL(best_dependency->logical_id, higher_logical_id);
    BOOST_CHECK_EQUAL(best_dependency->carrier, &higher_pending);
    BOOST_CHECK_EQUAL(best_dependency->best_candidate, &higher_pending);

    // The request lane may be empty after an exact certificate clears its
    // former dependency. The public tip callback must promote the best
    // remaining quarantine instead of waiting for another ConnectTip failure.
    BOOST_REQUIRE(llmq::chainLocksHandler != nullptr);
    {
        REVERSE_LOCK(main_lock);
        llmq::chainLocksHandler->UpdatedBlockTip(nullptr,
                                                 /*initial_download=*/true);
    }
    BOOST_CHECK(llmq::chainLocksHandler->IsPendingBTCCReceiptCertificate(
        higher_logical_id));

    uint256 unrelated_id{GetRandHash()};
    while (unrelated_id.IsNull() || unrelated_id == logical_id ||
           unrelated_id == higher_logical_id) {
        unrelated_id = GetRandHash();
    }
    BOOST_CHECK(
        !chainstate.ReconsiderBTCCReceiptCandidates(unrelated_id));
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(pending));

    BOOST_REQUIRE(
        chainstate.ReconsiderBTCCReceiptCandidates(logical_id));
    BOOST_CHECK(!chainstate.IsBTCCReceiptCandidateDeferred(pending));
    BOOST_CHECK(!chainstate.IsBTCCReceiptCandidateDeferred(descendant));
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(&pending), 1U);
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&descendant), 1U);
    for (CBlockIndex& restored : descendants) {
        BOOST_CHECK_EQUAL(
            chainstate.setBlockIndexCandidates.count(&restored), 1U);
    }
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(descendant_tip), 1U);
    BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*descendant_tip));
    BOOST_CHECK(chainstate.IsBTCCReceiptCandidateDeferred(higher_pending));
    chainman.CheckBlockIndex();
    const auto remaining_dependency{
        chainstate.GetBestDeferredBTCCReceiptCandidate()};
    BOOST_REQUIRE(remaining_dependency.has_value());
    BOOST_CHECK_EQUAL(remaining_dependency->logical_id, higher_logical_id);
    BOOST_REQUIRE(chainstate.ReconsiderBTCCReceiptCandidates(
        higher_logical_id));
    BOOST_CHECK(!chainstate.IsBTCCReceiptCandidateDeferred(higher_pending));
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&higher_pending), 1U);

    // Payment-audit receipts share the same ancestry-safe quarantine but
    // retain a domain-specific request and release lane.
    uint256 payment_hash{GetRandHash()};
    CBlockIndex payment_pending;
    payment_pending.phashBlock = &payment_hash;
    payment_pending.pprev = active_tip;
    payment_pending.nHeight = pending.nHeight;
    payment_pending.nChainWork = higher_pending.nChainWork + 1;
    payment_pending.nTx = 1;
    payment_pending.nChainTx = pending.nChainTx;
    payment_pending.nSequenceId = 1'500;
    payment_pending.nStatus =
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&payment_pending);
    uint256 payment_logical_id{GetRandHash()};
    while (payment_logical_id.IsNull() ||
           payment_logical_id == logical_id ||
           payment_logical_id == higher_logical_id) {
        payment_logical_id = GetRandHash();
    }
    BOOST_REQUIRE(chainstate.DeferPaymentAuditReceiptCandidates(
        payment_logical_id, payment_pending));
    BOOST_CHECK(chainstate.HasDeferredPaymentAuditReceiptCandidates(
        payment_logical_id));
    BOOST_CHECK(!chainstate.HasDeferredBTCCReceiptCandidates(
        payment_logical_id));
    const auto payment_dependency{
        chainstate.GetBestDeferredPaymentAuditReceiptCandidate()};
    BOOST_REQUIRE(payment_dependency);
    BOOST_CHECK_EQUAL(payment_dependency->logical_id,
                      payment_logical_id);
    BOOST_CHECK(!chainstate.ReconsiderBTCCReceiptCandidates(
        payment_logical_id));
    {
        REVERSE_LOCK(main_lock);
        llmq::chainLocksHandler->UpdatedBlockTip(nullptr,
                                                 /*initial_download=*/true);
    }
    // A synthetic carrier has no canonical block bytes on disk. Selection
    // must not synthesize a pending receipt from its witness ID.
    BOOST_CHECK(
        !llmq::chainLocksHandler
             ->IsPendingPaymentAuditReceiptCertificate(
                 payment_logical_id));

    llmq::pq::PaymentAuditReceipt known_payment_receipt;
    known_payment_receipt.has_audit = 1;
    known_payment_receipt.epoch = 1;
    known_payment_receipt.seal_height = payment_pending.nHeight - 10;
    known_payment_receipt.seal_block_hash = GetRandHash();
    known_payment_receipt.carrier_height = payment_pending.nHeight;
    known_payment_receipt.audit_logical_id = GetRandHash();
    known_payment_receipt.audit_witness_id = payment_logical_id;
    known_payment_receipt.commitment_hash = GetRandHash();
    known_payment_receipt.result_hash = GetRandHash();
    known_payment_receipt.next_probation_state_hash = GetRandHash();
    BOOST_REQUIRE(known_payment_receipt.IsStructurallyValid());
    llmq::chainLocksHandler->NotePendingPaymentAuditReceiptCertificate(
        known_payment_receipt, payment_pending);
    {
        REVERSE_LOCK(main_lock);
        llmq::chainLocksHandler->UpdatedBlockTip(nullptr,
                                                 /*initial_download=*/true);
    }
    BOOST_CHECK(
        llmq::chainLocksHandler
            ->IsPendingPaymentAuditReceiptCertificate(
                payment_logical_id));

    // A definitive exact-witness failure retires only its carrier branch.
    // Sibling carriers sharing the witness and unrelated witness IDs remain
    // quarantined and independently recoverable.
    uint256 payment_sibling_hash{GetRandHash()};
    CBlockIndex payment_sibling;
    payment_sibling.phashBlock = &payment_sibling_hash;
    payment_sibling.pprev = active_tip;
    payment_sibling.nHeight = payment_pending.nHeight;
    payment_sibling.nChainWork = higher_pending.nChainWork;
    payment_sibling.nTx = 1;
    payment_sibling.nChainTx = payment_pending.nChainTx;
    payment_sibling.nSequenceId = 1'501;
    payment_sibling.nStatus =
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&payment_sibling);
    BOOST_REQUIRE(chainstate.DeferPaymentAuditReceiptCandidates(
        payment_logical_id, payment_sibling));

    uint256 other_payment_hash{GetRandHash()};
    CBlockIndex other_payment;
    other_payment.phashBlock = &other_payment_hash;
    other_payment.pprev = active_tip;
    other_payment.nHeight = payment_pending.nHeight;
    other_payment.nChainWork = active_tip->nChainWork + 1;
    other_payment.nTx = 1;
    other_payment.nChainTx = payment_pending.nChainTx;
    other_payment.nSequenceId = 1'502;
    other_payment.nStatus =
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&other_payment);
    uint256 other_payment_id{GetRandHash()};
    while (other_payment_id.IsNull() ||
           other_payment_id == payment_logical_id) {
        other_payment_id = GetRandHash();
    }
    BOOST_REQUIRE(chainstate.DeferPaymentAuditReceiptCandidates(
        other_payment_id, other_payment));

    BOOST_REQUIRE(chainman.RetireDeferredPaymentAuditReceiptCarrier(
        payment_logical_id, payment_pending));
    BOOST_CHECK(payment_pending.nStatus & BLOCK_FAILED_VALID);
    BOOST_REQUIRE(chainman.m_blockman.WriteBlockIndexDB());
    BOOST_CHECK(chainstate.HasDeferredPaymentAuditReceiptCandidates(
        payment_logical_id));
    const auto surviving_payment{
        chainstate.GetBestDeferredPaymentAuditReceiptCandidate()};
    BOOST_REQUIRE(surviving_payment);
    BOOST_CHECK_EQUAL(surviving_payment->logical_id,
                      payment_logical_id);
    BOOST_CHECK_EQUAL(surviving_payment->carrier, &payment_sibling);
    BOOST_CHECK(chainstate.HasDeferredPaymentAuditReceiptCandidates(
        other_payment_id));

    BOOST_REQUIRE(chainstate.ReconsiderPaymentAuditReceiptCandidates(
        payment_logical_id));
    BOOST_CHECK(!chainstate.HasDeferredPaymentAuditReceiptCandidates(
        payment_logical_id));
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&payment_pending), 0U);
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&payment_sibling), 1U);
    BOOST_CHECK(chainstate.HasDeferredPaymentAuditReceiptCandidates(
        other_payment_id));
    BOOST_REQUIRE(chainstate.ReconsiderPaymentAuditReceiptCandidates(
        other_payment_id));
    BOOST_CHECK_EQUAL(
        chainstate.setBlockIndexCandidates.count(&other_payment), 1U);

    chainstate.ResetBlockFailureFlags(&payment_pending);
    BOOST_REQUIRE(chainman.m_blockman.WriteBlockIndexDB());
    {
        REVERSE_LOCK(main_lock);
        llmq::chainLocksHandler->UpdatedBlockTip(nullptr,
                                                 /*initial_download=*/true);
    }
    BOOST_CHECK(
        !llmq::chainLocksHandler
             ->IsPendingPaymentAuditReceiptCertificate(
                 payment_logical_id));

    // A runtime conflict on an ancestor before the carrier must retire the
    // hidden branch immediately. Quarantined descendants do not pass through
    // FindMostWorkChain, so they cannot rely on its failed-child propagation.
    uint256 conflict_ancestor_hash{GetRandHash()};
    uint256 conflict_carrier_hash{GetRandHash()};
    CBlockIndex conflict_ancestor;
    conflict_ancestor.phashBlock = &conflict_ancestor_hash;
    conflict_ancestor.pprev = active_tip;
    conflict_ancestor.nHeight = active_tip->nHeight + 1;
    conflict_ancestor.nChainWork = higher_pending.nChainWork + 1;
    conflict_ancestor.nTx = 1;
    conflict_ancestor.nChainTx = active_tip->nChainTx + 1;
    conflict_ancestor.nSequenceId = 2000;
    conflict_ancestor.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    CBlockIndex conflict_carrier;
    conflict_carrier.phashBlock = &conflict_carrier_hash;
    conflict_carrier.pprev = &conflict_ancestor;
    conflict_carrier.nHeight = conflict_ancestor.nHeight + 1;
    conflict_carrier.nChainWork = conflict_ancestor.nChainWork + 1;
    conflict_carrier.nTx = 1;
    conflict_carrier.nChainTx = conflict_ancestor.nChainTx + 1;
    conflict_carrier.nSequenceId = 2001;
    conflict_carrier.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    chainstate.TryAddBlockIndexCandidate(&conflict_carrier);
    uint256 conflict_logical_id{GetRandHash()};
    while (conflict_logical_id.IsNull() ||
           conflict_logical_id == logical_id ||
           conflict_logical_id == higher_logical_id) {
        conflict_logical_id = GetRandHash();
    }
    BOOST_REQUIRE(chainstate.DeferBTCCReceiptCandidates(
        conflict_logical_id, conflict_carrier));
    BlockValidationState conflict_state;
    BOOST_REQUIRE(chainstate.MarkConflictingBlock(conflict_state,
                                                   &conflict_ancestor));
    BOOST_CHECK(!chainstate.HasDeferredBTCCReceiptCandidates(
        conflict_logical_id));
    BOOST_CHECK(!chainstate.IsBTCCReceiptCandidateDeferred(
        conflict_carrier));
    conflict_ancestor.nStatus &= ~BLOCK_CONFLICT_CHAINLOCK;

    // Once the sibling is active, the equal-work quarantine is no longer a
    // useful retry candidate and is garbage-collected with normal pruning.
    BOOST_REQUIRE(
        chainstate.DeferBTCCReceiptCandidates(logical_id, *descendant_tip));
    chainstate.setBlockIndexCandidates.erase(&sibling);
    sibling.nChainWork = descendant_tip->nChainWork;
    chainstate.setBlockIndexCandidates.insert(&sibling);
    chainstate.m_chain.SetTip(sibling);
    chainstate.PruneBlockIndexCandidates();
    BOOST_CHECK(!chainstate.HasDeferredBTCCReceiptCandidates(logical_id));
    BOOST_CHECK(!chainstate.IsBTCCReceiptCandidateDeferred(pending));
    BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(&sibling), 1U);
    BOOST_CHECK(
        !chainstate.ReconsiderBTCCReceiptCandidates(logical_id));
    {
        REVERSE_LOCK(main_lock);
        llmq::chainLocksHandler->UpdatedBlockTip(nullptr,
                                                 /*initial_download=*/true);
    }
    BOOST_CHECK(!llmq::chainLocksHandler->IsPendingBTCCReceiptCertificate(
        higher_logical_id));
}

// A locally available block backlog may use compact payment-audit replay even
// after IBD has latched false, but a live carrier or an unrelated/header-only
// future must keep requesting its exact audit certificate.
BOOST_FIXTURE_TEST_CASE(
    payment_audit_historical_preseal_requires_signable_block_backlog,
    TestChain100Setup)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    const auto schedule{llmq::pq::MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule.has_value());

    LOCK(::cs_main);
    CBlockIndex* const original_tip{chainstate.m_chain.Tip()};
    BOOST_REQUIRE(original_tip != nullptr);
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    const int32_t carrier_height{
        schedule->epoch_origin +
        static_cast<int32_t>(llmq::pq::PQ_FIRST_ELIGIBLE_TARGET_OFFSET)};
    const int32_t later_target{
        carrier_height + static_cast<int32_t>(schedule->chainlock_period)};
    const auto signing_height{
        llmq::pq::SigningHeightForTarget(*schedule, later_target)};
    BOOST_REQUIRE(signing_height.has_value());
    BOOST_REQUIRE(original_tip->nHeight < carrier_height);
    BOOST_REQUIRE(llmq::pq::IsEligibleChainLockTarget(
        *schedule, carrier_height));
    BOOST_REQUIRE(llmq::pq::IsEligibleChainLockTarget(
        *schedule, later_target));

    const std::size_t branch_size{static_cast<std::size_t>(
        *signing_height - original_tip->nHeight)};
    std::vector<uint256> hashes(branch_size);
    std::vector<CBlockIndex> branch(branch_size);
    CBlockIndex* previous{original_tip};
    for (std::size_t i{0}; i < branch.size(); ++i) {
        hashes[i] = GetRandHash();
        CBlockIndex& index{branch[i]};
        index.phashBlock = &hashes[i];
        index.pprev = previous;
        index.nHeight = previous->nHeight + 1;
        index.nChainWork = previous->nChainWork + 1;
        index.nTx = 1;
        index.nChainTx = previous->nChainTx + 1;
        index.nSequenceId = static_cast<int32_t>(i + 1);
        index.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        index.BuildSkip();
        previous = &index;
    }
    const auto at_height = [&](int32_t height) -> CBlockIndex* {
        BOOST_REQUIRE(height > original_tip->nHeight);
        return &branch[static_cast<std::size_t>(
            height - original_tip->nHeight - 1)];
    };
    CBlockIndex* const carrier{at_height(carrier_height)};
    CBlockIndex* const before_signing{at_height(*signing_height - 1)};
    CBlockIndex* const signable_tip{at_height(*signing_height)};

    const auto original_candidates{chainstate.setBlockIndexCandidates};
    struct RestoreChainstate {
        Chainstate& chainstate;
        CBlockIndex* tip;
        std::set<CBlockIndex*, node::CBlockIndexWorkComparator> candidates;
        ~RestoreChainstate()
        {
            chainstate.ClearBlockIndexCandidates();
            chainstate.m_chain.SetTip(*tip);
            chainstate.setBlockIndexCandidates = std::move(candidates);
        }
    } restore{chainstate, original_tip, original_candidates};
    const auto select_candidate = [&](CBlockIndex* candidate) {
        chainstate.setBlockIndexCandidates.clear();
        chainstate.setBlockIndexCandidates.insert(original_tip);
        chainstate.setBlockIndexCandidates.insert(candidate);
    };

    // The carrier itself and a branch one block short of the later target's
    // signing height are live/uncoverable, despite being the most-work branch.
    select_candidate(carrier);
    BOOST_CHECK(!IsPaymentAuditHistoricalPresealCoverable(
        chainman, *carrier, *schedule));
    select_candidate(before_signing);
    BOOST_CHECK(!IsPaymentAuditHistoricalPresealCoverable(
        chainman, *carrier, *schedule));

    // Once all blocks through the signing height are locally available, the
    // current most-work backlog can durably wait for its covering CLSIG.
    select_candidate(signable_tip);
    BOOST_CHECK(IsPaymentAuditHistoricalPresealCoverable(
        chainman, *carrier, *schedule));

    // A same-height carrier on another fork cannot borrow that opportunity.
    uint256 fork_hash{GetRandHash()};
    CBlockIndex fork_carrier;
    fork_carrier.phashBlock = &fork_hash;
    fork_carrier.pprev = carrier->pprev;
    fork_carrier.nHeight = carrier->nHeight;
    fork_carrier.nChainWork = carrier->nChainWork;
    fork_carrier.nTx = 1;
    fork_carrier.nChainTx = carrier->nChainTx;
    fork_carrier.nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    BOOST_CHECK(!IsPaymentAuditHistoricalPresealCoverable(
        chainman, fork_carrier, *schedule));

    // Replay of an already-active historical prefix has the same requirement,
    // including retaining every intervening block needed for deferred NEVM.
    chainstate.m_chain.SetTip(*signable_tip);
    BOOST_CHECK(IsPaymentAuditHistoricalPresealCoverable(
        chainman, *carrier, *schedule));
    CBlockIndex* const target{at_height(later_target)};
    const BlockStatus original_status{target->nStatus};
    target->nStatus = static_cast<BlockStatus>(
        target->nStatus & ~BLOCK_HAVE_DATA);
    BOOST_CHECK(!IsPaymentAuditHistoricalPresealCoverable(
        chainman, *carrier, *schedule));
    target->nStatus = original_status;
}

// SYSCOIN END: PQ migration and payment-audit chainstate-manager regressions.

struct SnapshotTestSetup : TestChain100Setup {
    // Run with coinsdb on the filesystem to support, e.g., moving invalidated
    // chainstate dirs to "*_invalid".
    //
    // Note that this means the tests run considerably slower than in-memory DB
    // tests, but we can't otherwise test this functionality since it relies on
    // destructive filesystem operations.
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {},
                              // SYSCOIN
                              COINBASE_MATURITY,
                              /*coins_db_in_memory=*/false,
                              /*block_tree_db_in_memory=*/false,
                          }
    {
    }

    std::tuple<Chainstate*, Chainstate*> SetupSnapshot()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_CHECK(!chainman.IsSnapshotActive());

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.IsSnapshotValidated());
            BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));
        }

        size_t initial_size;
        size_t initial_total_coins{100};

        // Make some initial assertions about the contents of the chainstate.
        {
            LOCK(::cs_main);
            CCoinsViewCache& ibd_coinscache = chainman.ActiveChainstate().CoinsTip();
            initial_size = ibd_coinscache.GetCacheSize();
            size_t total_coins{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                BOOST_CHECK(ibd_coinscache.HaveCoin(op));
                total_coins++;
            }

            BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            BOOST_CHECK_EQUAL(initial_size, initial_total_coins);
        }

        Chainstate& validation_chainstate = chainman.ActiveChainstate();

        // Snapshot should refuse to load at this height.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(!chainman.SnapshotBlockhash());

        // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
        // be found.
        constexpr int snapshot_height = 110;
        mineBlocks(10);
        initial_size += 10;
        initial_total_coins += 10;

        // Should not load malleated snapshots
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // A UTXO is missing but count is correct
                metadata.m_coins_count -= 1;

                COutPoint outpoint;
                Coin coin;

                auto_infile >> outpoint;
                auto_infile >> coin;
        }));

        BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));

        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is larger than coins in file
                metadata.m_coins_count += 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is smaller than coins in file
                metadata.m_coins_count -= 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ZEROV;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ONEV;
        }));

        BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(fs::exists(*node::FindSnapshotChainstateDir(chainman.m_options.datadir)));

        // Ensure our active chain is the snapshot chainstate.
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            *chainman.SnapshotBlockhash());

        Chainstate& snapshot_chainstate = chainman.ActiveChainstate();

        {
            LOCK(::cs_main);

            fs::path found = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);

            // Note: WriteSnapshotBaseBlockhash() is implicitly tested above.
            BOOST_CHECK_EQUAL(
                *node::ReadSnapshotBaseBlockhash(found),
                *chainman.SnapshotBlockhash());

            // Ensure that the genesis block was not marked assumed-valid.
            BOOST_CHECK(!chainman.ActiveChain().Genesis()->IsAssumedValid());
        }

        const auto& au_data = ::Params().AssumeutxoForHeight(snapshot_height);
        const CBlockIndex* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

        BOOST_CHECK_EQUAL(tip->nChainTx, au_data->nChainTx);

        // To be checked against later when we try loading a subsequent snapshot.
        uint256 loaded_snapshot_blockhash{*chainman.SnapshotBlockhash()};

        // Make some assertions about the both chainstates. These checks ensure the
        // legacy chainstate hasn't changed and that the newly created chainstate
        // reflects the expected content.
        {
            LOCK(::cs_main);
            int chains_tested{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();

                // Both caches will be empty initially.
                BOOST_CHECK_EQUAL((unsigned int)0, coinscache.GetCacheSize());

                size_t total_coins{0};

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    BOOST_CHECK(coinscache.HaveCoin(op));
                    total_coins++;
                }

                BOOST_CHECK_EQUAL(initial_size , coinscache.GetCacheSize());
                BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
                chains_tested++;
            }

            BOOST_CHECK_EQUAL(chains_tested, 2);
        }

        // Mine some new blocks on top of the activated snapshot chainstate.
        constexpr size_t new_coins{100};
        mineBlocks(new_coins);  // Defined in TestChain100Setup.

        {
            LOCK(::cs_main);
            size_t coins_in_active{0};
            size_t coins_in_background{0};
            size_t coins_missing_from_background{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();
                bool is_background = chainstate != &chainman.ActiveChainstate();

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    if (coinscache.HaveCoin(op)) {
                        (is_background ? coins_in_background : coins_in_active)++;
                    } else if (is_background) {
                        coins_missing_from_background++;
                    }
                }
            }

            BOOST_CHECK_EQUAL(coins_in_active, initial_total_coins + new_coins);
            BOOST_CHECK_EQUAL(coins_in_background, initial_total_coins);
            BOOST_CHECK_EQUAL(coins_missing_from_background, new_coins);
        }

        // Snapshot should refuse to load after one has already loaded.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));

        // Snapshot blockhash should be unchanged.
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            loaded_snapshot_blockhash);
        return std::make_tuple(&validation_chainstate, &snapshot_chainstate);
    }

    // Simulate a restart of the node by flushing all state to disk, clearing the
    // existing ChainstateManager, and unloading the block index.
    //
    // @returns a reference to the "restarted" ChainstateManager
    ChainstateManager& SimulateNodeRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_TEST_MESSAGE("Simulating node restart");
        {
            for (Chainstate* cs : chainman.GetAll()) {
                LOCK(::cs_main);
                cs->ForceFlushStateToDisk();
            }
            // Process all callbacks referring to the old manager before wiping it.
            SyncWithValidationInterfaceQueue();
            LOCK(::cs_main);
            chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(m_node.exit_status);
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = chainman.m_options.datadir,
                .adjusted_time_callback = GetAdjustedTime,
                .notifications = *m_node.notifications,
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
            };
            // For robustness, ensure the old manager is destroyed before creating a
            // new one.
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(m_node.kernel->interrupt, chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    }
};

//! Test basic snapshot activation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot, SnapshotTestSetup)
{
    this->SetupSnapshot();
}

//! Test LoadBlockIndex behavior when multiple chainstates are in use.
//!
//! - First, verify that setBlockIndexCandidates is as expected when using a single,
//!   fully-validating chainstate.
//!
//! - Then mark a region of the chain BLOCK_ASSUMED_VALID and introduce a second chainstate
//!   that will tolerate assumed-valid blocks. Run LoadBlockIndex() and ensure that the first
//!   chainstate only contains fully validated blocks and the other chainstate contains all blocks,
//!   except those marked assume-valid, because those entries don't HAVE_DATA.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    int num_assumed_valid{0};
    // Blocks in range [assumed_valid_start_idx, last_assumed_valid_idx) will be
    // marked as assumed-valid and not having data.
    const int expected_assumed_valid{20};
    const int last_assumed_valid_idx{111};
    const int assumed_valid_start_idx = last_assumed_valid_idx - expected_assumed_valid;

    // Mine to height 120, past the hardcoded regtest assumeutxo snapshot at
    // height 110
    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* assumed_base{nullptr};
    CBlockIndex* assumed_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);

    auto reload_all_block_indexes = [&]() {
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        WITH_LOCK(::cs_main, return chainman.ResetBlockSequenceCounters());
        for (Chainstate* cs : chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ClearBlockIndexCandidates();
            BOOST_CHECK(cs->setBlockIndexCandidates.empty());
        }

        WITH_LOCK(::cs_main, chainman.LoadBlockIndex());
    };

    // Ensure that without any assumed-valid BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_all_block_indexes();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Mark some region of the chain assumed-valid, and remove the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked ASSUMED_VALID
        if (i < last_assumed_valid_idx && i >= assumed_valid_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE | BlockStatus::BLOCK_ASSUMED_VALID;
        }

        ++num_indexes;
        if (index->IsAssumedValid()) ++num_assumed_valid;

        // Note the last fully-validated block as the expected validated tip.
        if (i == (assumed_valid_start_idx - 1)) {
            validated_tip = index;
            BOOST_CHECK(!index->IsAssumedValid());
        }
        // Note the last assumed valid block as the snapshot base
        if (i == last_assumed_valid_idx - 1) {
            assumed_base = index;
            BOOST_CHECK(index->IsAssumedValid());
        } else if (i == last_assumed_valid_idx) {
            BOOST_CHECK(!index->IsAssumedValid());
        }
    }

    BOOST_CHECK_EQUAL(expected_assumed_valid, num_assumed_valid);

    // Note: cs2's tip is not set when ActivateExistingSnapshot is called.
    Chainstate& cs2 = WITH_LOCK(::cs_main,
        return chainman.ActivateExistingSnapshot(*assumed_base->phashBlock));

    // Set tip of the fully validated chain to be the validated tip
    cs1.m_chain.SetTip(*validated_tip);

    // Set tip of the assume-valid-based chain to the assume-valid block
    cs2.m_chain.SetTip(*assumed_base);

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // current cs1 chain has height 90
    BOOST_CHECK_EQUAL(assumed_base->nHeight, 110); // current cs2 chain has height 110

    // Regenerate cs1.setBlockIndexCandidates and cs2.setBlockIndexCandidate and
    // check contents below.
    reload_all_block_indexes();

    // The fully validated chain should only have the current validated tip and
    // the assumed valid base as candidates, blocks 90 and 110. Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-109 because they do not contain data.
    //
    // - It has block 110 even though it does not have data, because
    //   LoadBlockIndex has a special case to always add the snapshot block as a
    //   candidate. The special case is only actually intended to apply to the
    //   snapshot chainstate cs2, not the background chainstate cs1, but it is
    //   written broadly and applies to both.
    //
    // - It does not have any blocks after height 110 because cs1 is a background
    //   chainstate, and only blocks where are ancestors of the snapshot block
    //   are added as candidates for the background chainstate.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 2);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base), 1);

    // The assumed-valid tolerant chain has the assumed valid base as a
    // candidate, but otherwise has none of the assumed-valid (which do not
    // HAVE_DATA) blocks as candidates.
    //
    // Specifically:
    // - All blocks below height 110 are not candidates, because cs2 chain tip
    //   has height 110 and they have less work than it does.
    //
    // - Block 110 is a candidate even though it does not have data, because it
    //   is the snapshot block, which is assumed valid.
    //
    // - Blocks 111-120 are added because they have data.

    // Check that block 90 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(validated_tip), 0);
    // Check that block 109 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base->pprev), 0);
    // Check that block 110 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base), 1);
    // Check that block 120 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_tip), 1);
    // Check that 11 blocks total are present.
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.size(), num_indexes - last_assumed_valid_idx + 1);
}

//! Ensure that snapshot chainstates initialize properly when found on disk.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_init, SnapshotTestSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& bg_chainstate = chainman.ActiveChainstate();

    this->SetupSnapshot();

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 2);

    // "Rewind" the background chainstate so that its tip is not at the
    // base block of the snapshot - this is so after simulating a node restart,
    // it will initialize instead of attempting to complete validation.
    //
    // Note that this is not a realistic use of DisconnectTip().
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_SIZE * 1000};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, bg_chainstate.MempoolMutex());
        BOOST_CHECK(bg_chainstate.DisconnectTip(unused_state, &unused_pool));
        unused_pool.clear();  // to avoid queuedTx assertion errors on teardown
    }
    BOOST_CHECK_EQUAL(bg_chainstate.m_chain.Height(), 109);

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates.
    this->LoadVerifyActivateChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 2);
        BOOST_CHECK(chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the initialized snapshot chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);

        // Background chainstate should be unaware of new blocks on the snapshot
        // chainstate.
        for (Chainstate* cs : chainman_restarted.GetAll()) {
            if (cs != &chainman_restarted.ActiveChainstate()) {
                BOOST_CHECK_EQUAL(cs->m_chain.Height(), 109);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion, SnapshotTestSetup)
{
    this->SetupSnapshot();

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& active_cs = chainman.ActiveChainstate();
    auto tip_cache_before_complete = active_cs.m_coinstip_cache_size_bytes;
    auto db_cache_before_complete = active_cs.m_coinsdb_cache_size_bytes;

    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SUCCESS);

    WITH_LOCK(::cs_main, BOOST_CHECK(chainman.IsSnapshotValidated()));
    BOOST_CHECK(chainman.IsSnapshotActive());

    // Cache should have been rebalanced and reallocated to the "only" remaining
    // chainstate.
    BOOST_CHECK(active_cs.m_coinstip_cache_size_bytes > tip_cache_before_complete);
    BOOST_CHECK(active_cs.m_coinsdb_cache_size_bytes > db_cache_before_complete);

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &active_cs);

    // Trying completion again should return false.
    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SKIPPED);

    // The invalid snapshot path should not have been used.
    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should still exist.
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should now *not* exist.
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    const Chainstate& active_cs2 = chainman_restarted.ActiveChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK(active_cs2.m_coinstip_cache_size_bytes > tip_cache_before_complete);
        BOOST_CHECK(active_cs2.m_coinsdb_cache_size_bytes > db_cache_before_complete);

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion_hash_mismatch, SnapshotTestSetup)
{
    auto chainstates = this->SetupSnapshot();
    Chainstate& validation_chainstate = *std::get<0>(chainstates);
    ChainstateManager& chainman = *Assert(m_node.chainman);
    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Test tampering with the IBD UTXO set with an extra coin to ensure it causes
    // snapshot completion to fail.
    CCoinsViewCache& ibd_coins = WITH_LOCK(::cs_main,
        return validation_chainstate.CoinsTip());
    Coin badcoin;
    badcoin.out.nValue = InsecureRand32();
    badcoin.nHeight = 1;
    badcoin.out.scriptPubKey.assign(InsecureRandBits(6), 0);
    uint256 txid = InsecureRand256();
    ibd_coins.AddCoin(COutPoint(txid, 0), std::move(badcoin), false);

    fs::path snapshot_chainstate_dir = gArgs.GetDataDirNet() / "chainstate_snapshot";
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    {
        ASSERT_DEBUG_LOG("failed to validate the -assumeutxo snapshot state");
        res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
        BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::HASH_MISMATCH);
    }

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &validation_chainstate);
    BOOST_CHECK_EQUAL(&chainman.ActiveChainstate(), &validation_chainstate);

    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(fs::exists(snapshot_invalid_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully loads only the fully-validated
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(fs::exists(snapshot_invalid_dir));
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_AUTO_TEST_SUITE_END()
