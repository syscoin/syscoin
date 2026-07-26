// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <addresstype.h>
#include <consensus/validation.h>
#include <governance/governanceclasses.h>
#include <governance/governanceexceptions.h>
#include <governance/governancevote.h>
#include <masternode/masternodepayments.h>
#include <masternode/masternodesync.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/coins.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>

#include <vector>

#include <boost/test/unit_test.hpp>

namespace governance_tests {

class CGovernanceManagerTestAccess
{
public:
    static bool AddTriggerAtHeight(
        CGovernanceManager& manager,
        int observed_height,
        CGovernanceObject&& trigger,
        uint256& trigger_hash)
    {
        const int active_height = WITH_LOCK(
            manager.chainman.GetMutex(),
            return manager.chainman.ActiveHeight());
        trigger_hash = trigger.GetHash();
        LOCK(manager.cs);
        manager.nCachedBlockHeight = observed_height;
        const auto [it, inserted] =
            manager.mapObjects.emplace(trigger_hash, std::move(trigger));
        return inserted &&
            manager.AddNewTrigger(trigger_hash, active_height);
    }

    static bool ProcessVoteAtHeight(
        CGovernanceManager& manager,
        int observed_height,
        const CGovernanceVote& vote,
        CGovernanceException& exception,
        CConnman& connman)
    {
        {
            LOCK(manager.cs);
            manager.nCachedBlockHeight = observed_height;
        }
        return manager.ProcessVote(
            /*pfrom=*/nullptr, vote, exception, connman);
    }

    static bool InsertPreviouslyAdmittedTrigger(
        CGovernanceManager& manager,
        CGovernanceObject&& trigger,
        uint256& trigger_hash)
    {
        trigger_hash = trigger.GetHash();
        LOCK(manager.cs);
        const auto [it, inserted] =
            manager.mapObjects.emplace(trigger_hash, std::move(trigger));
        if (!inserted) return false;

        auto superblock = std::make_shared<CSuperblock>(trigger_hash);
        superblock->SetStatus(SeenObjectStatus::Valid);
        return manager.mapTrigger.emplace(
            trigger_hash, std::move(superblock)).second;
    }
};

} // namespace governance_tests

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

//! Test resizing coins-related Chainstate caches during runtime.
//!
BOOST_AUTO_TEST_CASE(validation_chainstate_resize_caches)
{
    ChainstateManager& manager = *Assert(m_node.chainman);
    CTxMemPool& mempool = *Assert(m_node.mempool);
    Chainstate& c1 = WITH_LOCK(cs_main, return manager.InitializeChainstate(&mempool));
    c1.InitCoinsDB(
        /* cache_size_bytes */ 1 << 23, /* in_memory */ true, /* should_wipe */ false);
    WITH_LOCK(::cs_main, c1.InitCoinsCache(1 << 23));
    BOOST_REQUIRE(c1.LoadGenesisBlock()); // Need at least one block loaded to be able to flush caches

    // Add a coin to the in-memory cache, upsize once, then downsize.
    {
        LOCK(::cs_main);
        const auto outpoint = AddTestCoin(c1.CoinsTip());

        // Set a meaningless bestblock value in the coinsview cache - otherwise we won't
        // flush during ResizecoinsCaches() and will subsequently hit an assertion.
        c1.CoinsTip().SetBestBlock(InsecureRand256());

        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 24,  // upsizing the coinsview cache
            1 << 22  // downsizing the coinsdb cache
        );

        // View should still have the coin cached, since we haven't destructed the cache on upsize.
        BOOST_CHECK(c1.CoinsTip().HaveCoinInCache(outpoint));

        c1.ResizeCoinsCaches(
            1 << 22,  // downsizing the coinsview cache
            1 << 23  // upsizing the coinsdb cache
        );

        // The view cache should be empty since we had to destruct to downsize.
        BOOST_CHECK(!c1.CoinsTip().HaveCoinInCache(outpoint));
    }
}

//! Test UpdateTip behavior for both active and background chainstates.
//!
//! When run on the background chainstate, UpdateTip should do a subset
//! of what it does for the active chainstate.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    uint256 curr_tip = ::g_best_block;

    // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
    // be found.
    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    // Grab block 1 from disk; we'll add it to the background chain later.
    std::shared_ptr<CBlock> pblockone = std::make_shared<CBlock>();
    {
        LOCK(::cs_main);
        chainman.m_blockman.ReadBlockFromDisk(*pblockone, *chainman.ActiveChain()[1]);
    }

    BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(
        this, NoMalleation, /*reset_chainstate=*/ true));

    // Ensure our active chain is the snapshot chainstate.
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.IsSnapshotActive()));

    curr_tip = ::g_best_block;

    // Mine a new block on top of the activated snapshot chainstate.
    mineBlocks(1);  // Defined in TestChain100Setup.

    // After adding some blocks to the snapshot tip, best block should have changed.
    BOOST_CHECK(::g_best_block != curr_tip);

    curr_tip = ::g_best_block;

    BOOST_CHECK_EQUAL(chainman.GetAll().size(), 2U);

    Chainstate& background_cs{*[&] {
        for (Chainstate* cs : chainman.GetAll()) {
            if (cs != &chainman.ActiveChainstate()) {
                return cs;
            }
        }
        assert(false);
    }()};

    // Append the first block to the background chain.
    BlockValidationState state;
    CBlockIndex* pindex = nullptr;
    const CChainParams& chainparams = Params();
    bool newblock = false;

    // TODO: much of this is inlined from ProcessNewBlock(); just reuse PNB()
    // once it is changed to support multiple chainstates.
    {
        LOCK(::cs_main);
        bool checked = CheckBlock(*pblockone, state, chainparams.GetConsensus());
        BOOST_CHECK(checked);
        bool accepted = chainman.AcceptBlock(
            pblockone, state, &pindex, true, nullptr, &newblock, true);
        BOOST_CHECK(accepted);
    }

    // UpdateTip is called here
    bool block_added = background_cs.ActivateBestChain(state, pblockone);

    // Ensure tip is as expected
    BOOST_CHECK_EQUAL(background_cs.m_chain.Tip()->GetBlockHash(), pblockone->GetHash());

    // g_best_block should be unchanged after adding a block to the background
    // validation chain.
    BOOST_CHECK(block_added);
    BOOST_CHECK_EQUAL(curr_tip, ::g_best_block);
}

BOOST_FIXTURE_TEST_CASE(superblock_chainlock_requires_exact_governance_provenance,
                        TestChainDIP3V19Setup)
{
    struct SyncModeGuard {
        const int old_mode;
        ~SyncModeGuard() { masternodeSync.SetSyncMode(old_mode); }
    } sync_mode_guard{masternodeSync.GetAssetID()};

    const CBlockIndex* pindex;
    {
        LOCK(::cs_main);
        pindex = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_REQUIRE(pindex != nullptr);
    BOOST_REQUIRE(pindex->nHeight >= Params().GetConsensus().DIP0003Height);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(pindex->nHeight));

    const CAmount regular_reward =
        GetBlockSubsidy(pindex->nHeight, Params().GetConsensus());
    const CAmount unbacked_issuance = COIN;

    BOOST_REQUIRE(!m_coinbase_txns.empty());
    CMutableTransaction coinbase{*m_coinbase_txns.back()};
    coinbase.vout.emplace_back(unbacked_issuance, CScript() << OP_TRUE);

    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(coinbase));

    CAmount mn_seniority = 0;
    CAmount mn_floor_diff = 0;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(IsBlockPayeeValid(m_node.chainman->ActiveChain(),
                                        *block.vtx[0], pindex->nHeight,
                                        regular_reward, /*fees=*/0, mn_seniority,
                                        mn_floor_diff));
    }
    const CAmount value_limit =
        regular_reward + mn_seniority + mn_floor_diff;
    BOOST_REQUIRE_EQUAL(m_coinbase_txns.back()->GetValueOut(), value_limit);
    BOOST_REQUIRE_EQUAL(block.vtx[0]->GetValueOut(),
                        value_limit + unbacked_issuance);

    std::string error;
    bool exact_superblock_validation{true};

    // The historical sync fallback remains bounded by the adaptive cap, but
    // must not produce exact-governance provenance for ChainLock signing.
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
    BOOST_REQUIRE(masternodeSync.IsBlockchainSynced());
    BOOST_REQUIRE(!masternodeSync.IsSynced());
    BOOST_CHECK(IsBlockValueValid(block, pindex, value_limit, error,
                                  /*fJustCheck=*/true,
                                  /*check_superblock=*/true,
                                  &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);

    masternodeSync.SetSyncMode(MASTERNODE_SYNC_FINISHED);
    error.clear();
    exact_superblock_validation = false;
    BOOST_CHECK(!IsBlockValueValid(block, pindex, value_limit, error,
                                   /*fJustCheck=*/true,
                                   /*check_superblock=*/true,
                                   &exact_superblock_validation));
    BOOST_CHECK(exact_superblock_validation);

    // Equal height is not historical: the ChainLocked block itself must take
    // the exact path. Only a strict ancestor may set this predicate false.
    const int best_chainlock_height = pindex->nHeight;
    const bool check_superblock =
        best_chainlock_height <= pindex->nHeight;
    BOOST_REQUIRE(check_superblock);

    error.clear();
    exact_superblock_validation = false;
    BOOST_CHECK(!IsBlockValueValid(block, pindex, value_limit, error,
                                   /*fJustCheck=*/true, check_superblock,
                                   &exact_superblock_validation));
    BOOST_CHECK(exact_superblock_validation);

    error.clear();
    exact_superblock_validation = true;
    BOOST_CHECK(IsBlockValueValid(block, pindex, value_limit, error,
                                  /*fJustCheck=*/true,
                                  /*check_superblock=*/false,
                                  &exact_superblock_validation));
    BOOST_CHECK(!exact_superblock_validation);
}

BOOST_FIXTURE_TEST_CASE(
    past_superblock_trigger_and_funding_vote_are_rejected,
    TestChainDIP3V19Setup)
{
    const CBlockIndex* tip =
        WITH_LOCK(::cs_main, return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(tip != nullptr);
    const int event_height = tip->nHeight;
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(event_height));

    const CTxDestination destination =
        PKHash(coinbaseKey.GetPubKey());
    const auto make_trigger = [&](const int trigger_height,
                                  const uint256& proposal_hash) {
        std::vector<CGovernancePayment> payments;
        payments.emplace_back(destination, COIN, proposal_hash);
        CSuperblock schedule{trigger_height, std::move(payments)};
        return CGovernanceObject{
            uint256{},
            /*revision=*/1,
            GetTime<std::chrono::seconds>().count(),
            uint256{},
            schedule.GetHexStrData()};
    };

    uint256 late_trigger_hash;
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::
            AddTriggerAtHeight(
                *governance,
                event_height - 1,
                make_trigger(event_height, InsecureRand256()),
                late_trigger_hash));

    const int future_event_height =
        event_height +
        Params().GetConsensus().SuperBlockCycle(event_height);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(future_event_height));
    uint256 future_trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            AddTriggerAtHeight(
                *governance,
                event_height - 1,
                make_trigger(future_event_height, InsecureRand256()),
                future_trigger_hash));

    uint256 on_time_trigger_hash;
    BOOST_REQUIRE(
        governance_tests::CGovernanceManagerTestAccess::
            InsertPreviouslyAdmittedTrigger(
                *governance,
                make_trigger(event_height, InsecureRand256()),
                on_time_trigger_hash));

    CGovernanceVote late_funding_vote{
        COutPoint{InsecureRand256(), 0},
        on_time_trigger_hash,
        VOTE_SIGNAL_FUNDING,
        VOTE_OUTCOME_YES};
    CGovernanceException exception;
    BOOST_CHECK(
        !governance_tests::CGovernanceManagerTestAccess::
            ProcessVoteAtHeight(
                *governance,
                event_height - 1,
                late_funding_vote,
                exception,
                *m_node.connman));
    BOOST_CHECK_EQUAL(
        exception.GetType(), GOVERNANCE_EXCEPTION_WARNING);
    BOOST_CHECK_EQUAL(exception.GetNodePenalty(), 0);
    BOOST_CHECK(
        std::string{exception.what()}.find("event height has passed") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
