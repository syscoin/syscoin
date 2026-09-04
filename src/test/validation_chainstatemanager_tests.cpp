// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h> // SYSCOIN: deterministic valid-MN payout.
#include <chainparams.h>
#include <consensus/pq_migration_config.h> // SYSCOIN: PQ activation-boundary tests.
#include <consensus/validation.h>
#include <evo/deterministicmns.h> // SYSCOIN: deep rollback integration state.
#include <evo/pq_payment_probation_db.h> // SYSCOIN: multi-chainstate probation GC.
#include <evo/pq_registry.h> // SYSCOIN: deep rollback registry roots.
#include <kernel/disconnected_transactions.h>
#include <llmq/pq_chainlock_persistence.h> // SYSCOIN: pre-import durable finality.
#include <llmq/pq_chainlock_schedule.h> // SYSCOIN: payment-audit preseal coverage.
#include <llmq/quorums_chainlocks.h> // SYSCOIN: retained probation roots.
#include <llmq/quorums_init.h> // SYSCOIN: recreate pre-import finality handler.
#include <netbase.h> // SYSCOIN: deterministic valid-MN fixture service.
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/kernel_notifications.h>
#include <node/utxo_snapshot.h>
#include <pow.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/pq_test_util.h> // SYSCOIN: durable roster-context fixture.
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

#include <algorithm> // SYSCOIN: synthetic recovery-universe fixture.
#include <array> // SYSCOIN: synthetic PQ activation fixtures.
#include <cstdint> // SYSCOIN: synthetic recovery-authority fixture.
#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

namespace {
struct DeferredNEVMReplaySetup : TestChain100Setup {
    DeferredNEVMReplaySetup()
        : TestChain100Setup{ChainType::REGTEST,
                            {"-nevmstartheight=101"}} {}
};

bool ReplayDeferredForTest(Chainstate& chainstate,
                           int32_t through_height,
                           const uint256& through_hash,
                           const std::function<bool()>& finalize,
                           bool& complete,
                           std::string& error) NO_THREAD_SAFETY_ANALYSIS
{
    AssertLockNotHeld(::cs_main);
    return chainstate.ReplayDeferredBTCCNEVM(
        through_height, through_hash, finalize, complete, error);
}

void AssertMainLockHeldForTest() NO_THREAD_SAFETY_ANALYSIS
{
    AssertLockHeld(::cs_main);
}

// SYSCOIN BEGIN: Durable recovery-universe fixture.
uint256 RecoveryFixtureHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

llmq::pq::RecoveryUniverseCapsulePtr MakeRecoveryUniverseFixture(
    const uint256& genesis_hash,
    const llmq::pq::RecoveryRosterAuthoritySource& source,
    const CBlockIndex& source_snapshot)
{
    std::vector<llmq::pq::RecoveryUniverseMember> members;
    members.reserve(llmq::pq::QUORUM_SIZE);
    for (std::size_t index{0}; index < llmq::pq::QUORUM_SIZE; ++index) {
        members.push_back(llmq::pq::RecoveryUniverseMember{
            RecoveryFixtureHash(1 + index),
            RecoveryFixtureHash(1'000 + index),
            COutPoint{RecoveryFixtureHash(2'000 + index),
                      static_cast<uint32_t>(index)}});
    }
    std::sort(members.begin(), members.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    const uint256 source_id{
        llmq::pq::GetRecoveryUniverseSourceId(genesis_hash, source)};
    const uint256 members_hash{
        llmq::pq::GetRecoveryUniverseMembersHash(genesis_hash, members)};
    const uint256 capsule_id{llmq::pq::GetRecoveryUniverseCapsuleId(
        genesis_hash, source, source_snapshot.nHeight,
        source_snapshot.GetBlockHash(), members_hash, members.size())};

    DataStream stream{SER_DISK};
    stream << llmq::pq::RECOVERY_UNIVERSE_CAPSULE_VERSION << genesis_hash
           << source << source_snapshot.nHeight
           << source_snapshot.GetBlockHash() << source_id
           << static_cast<uint32_t>(members.size());
    for (const auto& member : members) stream << member;
    stream << members_hash << capsule_id;
    const std::vector<uint8_t> encoded{
        UCharCast(stream.data()), UCharCast(stream.data() + stream.size())};
    const auto decoded{
        llmq::pq::RecoveryUniverseCapsule::DecodeTrustedPersistence(encoded)};
    if (!decoded) return nullptr;
    return std::make_shared<const llmq::pq::RecoveryUniverseCapsule>(*decoded);
}
// SYSCOIN END: Durable recovery-universe fixture.

} // namespace

BOOST_FIXTURE_TEST_CASE(persisted_reindex_marker_forces_clean_block_index, ChainTestingSetup)
{
    struct ReindexFlagsGuard {
        const bool reindex{node::fReindex.load()};
        const bool reindex_geth{fReindexGeth.load()};
        ~ReindexFlagsGuard()
        {
            node::fReindex = reindex;
            fReindexGeth = reindex_geth;
        }
    } flags_guard;

    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path block_index_path = m_args.GetDataDirNet() / "blocks" / "index";
    {
        LOCK(::cs_main);
        chainman.m_blockman.m_block_tree_db.reset();
    }
    {
        kernel::BlockTreeDB block_tree{DBParams{
            .path = block_index_path,
            .cache_bytes = static_cast<size_t>(m_cache_sizes.block_tree_db),
            .memory_only = false,
            .wipe_data = true}};
        BOOST_REQUIRE(block_tree.WriteFlag("reindex-sentinel", true));
        BOOST_REQUIRE(block_tree.WriteReindexing(true));
    }

    node::fReindex = false;
    fReindexGeth = false;
    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.block_tree_db_in_memory = false;
    options.coins_db_in_memory = true;
    options.connman = Assert(m_node.connman.get());
    options.banman = Assert(m_node.banman.get());
    options.peerman = Assert(m_node.peerman.get());

    const auto [status, error] = node::LoadChainstate(chainman, m_cache_sizes, options);
    BOOST_REQUIRE_MESSAGE(status == node::ChainstateLoadStatus::SUCCESS, error.original);
    BOOST_CHECK(node::fReindex.load());
    BOOST_CHECK(fReindexGeth.load());

    {
        LOCK(::cs_main);
        bool sentinel{false};
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->ReadFlag("reindex-sentinel", sentinel));
        bool reindexing{false};
        chainman.m_blockman.m_block_tree_db->ReadReindexing(reindexing);
        BOOST_CHECK(reindexing);
    }
}
BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

// SYSCOIN BEGIN: Public IBD and durable recovery-marker lifecycle tests.
// and deferred NEVM recovery reach the exact active tip.
BOOST_FIXTURE_TEST_CASE(pq_history_auth_state_gates_public_ibd,
                        TestChain100Setup)
{
    auto& chainman{static_cast<TestChainstateManager&>(
        *Assert(m_node.chainman))};

    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(
        chainman.GetConsensus()));
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::READY);
    }
    chainman.ResetIbd(PQHistoryAuthState::UNINITIALIZED);
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsBaseBlockSyncComplete());
        BOOST_CHECK(chainman.PublishPQHistoryAuthState(
            PQHistoryAuthState::PENDING));
        BOOST_CHECK(chainman.CanBeginPQHistoryAuthentication());
    }
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.PublishPQHistoryAuthState(
            PQHistoryAuthState::READY));
    }
    BOOST_CHECK(!chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.CanBeginPQHistoryAuthentication());
        BOOST_CHECK(!chainman.PublishPQHistoryAuthState(
            PQHistoryAuthState::PENDING));
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::READY);
    }

    {
        LOCK(::cs_main);
        const CBlockIndex* tip{chainman.ActiveTip()};
        BOOST_REQUIRE(tip != nullptr);
        const CBlockIndex* branch_point{tip->pprev};
        BOOST_REQUIRE(branch_point != nullptr);
        CBlockIndex unrelated;
        unrelated.nHeight = branch_point->nHeight;
        BOOST_CHECK(!chainman.CanBeginPQHistoryAuthentication(
            unrelated, tip->nHeight));
        BOOST_CHECK(!chainman.CanBeginPQHistoryAuthentication(
            *branch_point, tip->nHeight + 1));
        BOOST_CHECK(chainman.CanBeginPQHistoryAuthentication(
            *branch_point, tip->nHeight));
        BOOST_CHECK(chainman.TryEnterPendingPQHistoryAuthentication(
            *branch_point, tip->nHeight));
        BOOST_CHECK(chainman.CanBeginPQHistoryAuthentication());
        BOOST_CHECK(chainman.PublishPQHistoryAuthState(
            PQHistoryAuthState::PENDING));
        BOOST_CHECK(chainman.PublishPQHistoryAuthState(
            PQHistoryAuthState::READY));
        BOOST_CHECK(!chainman.CanBeginPQHistoryAuthentication());
    }
    SyncWithValidationInterfaceQueue();
}

BOOST_FIXTURE_TEST_CASE(
    payment_checkpoint_without_durable_chainlock_keeps_history_pending,
    TestChain100Setup)
{
    auto& chainman{static_cast<TestChainstateManager&>(
        *Assert(m_node.chainman))};
    auto& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreState {
        Consensus::Params& consensus;
        Consensus::Params saved_consensus;
        ~RestoreState()
        {
            llmq::StopLLMQSystem();
            llmq::DestroyLLMQSystem();
            consensus = std::move(saved_consensus);
        }
    } restore{consensus, consensus};

    llmq::StopLLMQSystem();
    llmq::DestroyLLMQSystem();
    chainman.ResetIbd(PQHistoryAuthState::UNINITIALIZED);

    consensus.DIP0003Height = 1;
    consensus.nPQPreparationHeight = 1'000;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQActivationHeight = 2'305;
    consensus.nPQBTCCCandidateOrigin = 2'305;
    consensus.nPQBTCCNEVMInjectionLag =
        static_cast<int>(llmq::pq::PQ_BTCC_NEVM_LAG);
    consensus.nPQBTCCReceiptAnchorHeight = 1'000;
    consensus.hashPQBTCCReceiptAnchorBlock = GetRandHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();

    const auto config{
        llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_REQUIRE(llmq::MakePQQuorumBuildConfig(consensus));

    llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = 7;
    checkpoint.covered_through_height = 2'304;
    checkpoint.covered_through_hash = GetRandHash();
    checkpoint.authenticated_probation_state_hash = GetRandHash();
    checkpoint.authorizing_target_height = 2'305;
    checkpoint.authorizing_target_hash = GetRandHash();
    checkpoint.authorizing_chainlock_logical_id = GetRandHash();
    checkpoint.authorizing_chainlock_witness_id = GetRandHash();
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    {
        llmq::pq::PaymentAuditStore audit_store{
            chainman.m_options.datadir / "llmq/pq-payment-audits",
            consensus.hashGenesisBlock, 8U << 20, /*wipe=*/true};
        BOOST_REQUIRE(audit_store.PruneThroughCheckpoint(checkpoint));
    }
    {
        llmq::pq::PQChainLockPersistence persistence{
            DBParams{
                .path = chainman.m_options.datadir / "llmq/pq-chainlocks",
                .cache_bytes = 4U << 20,
                .wipe_data = true,
            },
            consensus.hashGenesisBlock, *config};
        BOOST_CHECK(!persistence.HasBest());
    }

    {
        LOCK(::cs_main);
        llmq::InitLLMQSystem(*Assert(m_node.connman),
                             *Assert(m_node.peerman), chainman);
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::PENDING);
    }
    BOOST_REQUIRE(llmq::chainLocksHandler != nullptr);

    // Start performs the synchronous Refresh pass. The checkpoint remains
    // recoverable rather than poisoning verification or being treated as an
    // authenticated standalone root.
    llmq::StartLLMQSystem();
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::PENDING);
    }
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK(llmq::chainLocksHandler->GetCLSIGFromPeers());
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_clears_only_at_exact_tip,
                        DeferredNEVMReplaySetup)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    const CBlockIndex* replay_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    BOOST_REQUIRE(replay_tip != nullptr);
    BOOST_REQUIRE_EQUAL(replay_tip->nHeight, 100);

    const bool previous_nevm_connection{fNEVMConnection};
    struct RestoreNEVMConnection {
        const bool previous;
        ~RestoreNEVMConnection() { fNEVMConnection = previous; }
    } restore_nevm_connection{previous_nevm_connection};

    fNEVMConnection = true;
    bool finalized{false};
    bool complete{false};
    std::string error;
    BOOST_REQUIRE(ReplayDeferredForTest(
        chainstate,
        replay_tip->nHeight, replay_tip->GetBlockHash(),
        [&] {
            AssertMainLockHeldForTest();
            finalized = true;
            return true;
        },
        complete, error));
    BOOST_CHECK(complete);
    BOOST_CHECK(finalized);
    BOOST_CHECK(error.empty());

    // Model a tip activated after a scheduler captured its replay target. The
    // older prefix is fully applied, but its marker must remain so the newly
    // connected block is included by the next replay pass.
    fNEVMConnection = false;
    mineBlocks(1);
    fNEVMConnection = true;
    finalized = false;
    complete = true;
    error.clear();
    BOOST_REQUIRE(ReplayDeferredForTest(
        chainstate,
        replay_tip->nHeight, replay_tip->GetBlockHash(),
        [&] {
            finalized = true;
            return true;
        },
        complete, error));
    BOOST_CHECK(!complete);
    BOOST_CHECK(!finalized);
    BOOST_CHECK(error.empty());
}

BOOST_AUTO_TEST_CASE(coins_recovery_marker_validation)
{
    const auto hash = [](uint8_t tag) {
        uint256 value;
        value.begin()[0] = tag;
        return value;
    };
    const uint256 old_tip{hash(1)};
    const uint256 new_tip{hash(2)};
    const uint256 conflicting_tip{hash(3)};
    std::string error;

    const auto normal{ChainstateManager::GetCoinsRecoveryMarkers(
        old_tip, std::span<const uint256>{}, new_tip, error)};
    BOOST_REQUIRE(normal.has_value());
    BOOST_REQUIRE_EQUAL(normal->size(), 2U);
    BOOST_CHECK((*normal)[0] == old_tip);
    BOOST_CHECK((*normal)[1] == new_tip);

    const std::array<uint256, 2> interrupted_heads{new_tip, old_tip};
    const auto interrupted{ChainstateManager::GetCoinsRecoveryMarkers(
        {}, interrupted_heads, new_tip, error)};
    BOOST_REQUIRE(interrupted.has_value());
    BOOST_REQUIRE_EQUAL(interrupted->size(), 2U);
    BOOST_CHECK((*interrupted)[0] == new_tip);
    BOOST_CHECK((*interrupted)[1] == old_tip);

    const std::array<uint256, 2> first_flush_heads{new_tip, uint256{}};
    const auto first_flush{ChainstateManager::GetCoinsRecoveryMarkers(
        {}, first_flush_heads, new_tip, error)};
    BOOST_REQUIRE(first_flush.has_value());
    BOOST_REQUIRE_EQUAL(first_flush->size(), 1U);
    BOOST_CHECK(first_flush->front() == new_tip);

    const auto never_flushed{ChainstateManager::GetCoinsRecoveryMarkers(
        {}, std::span<const uint256>{}, new_tip, error)};
    BOOST_REQUIRE(never_flushed.has_value());
    BOOST_REQUIRE_EQUAL(never_flushed->size(), 1U);
    BOOST_CHECK(never_flushed->front() == new_tip);

    const auto empty{ChainstateManager::GetCoinsRecoveryMarkers(
        {}, std::span<const uint256>{}, {}, error)};
    BOOST_REQUIRE(empty.has_value());
    BOOST_CHECK(empty->empty());

    BOOST_CHECK(!ChainstateManager::GetCoinsRecoveryMarkers(
                     {}, interrupted_heads, conflicting_tip, error)
                     .has_value());
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!ChainstateManager::GetCoinsRecoveryMarkers(
                     old_tip, interrupted_heads, new_tip, error)
                     .has_value());
    const std::array<uint256, 1> malformed_heads{new_tip};
    BOOST_CHECK(!ChainstateManager::GetCoinsRecoveryMarkers(
                     {}, malformed_heads, new_tip, error)
                     .has_value());
    const std::array<uint256, 2> null_new_head{uint256{}, old_tip};
    BOOST_CHECK(!ChainstateManager::GetCoinsRecoveryMarkers(
                     {}, null_new_head, {}, error)
                     .has_value());
}
// SYSCOIN END: Public IBD and durable recovery-marker lifecycle tests.

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

// SYSCOIN: GC must retain roots referenced by every chainstate recovery marker.
BOOST_FIXTURE_TEST_CASE(
    payment_probation_gc_retains_every_chainstate_recovery_marker,
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
        const auto roots{
            llmq::CollectChainstatePaymentProbationRoots(chainman)};
        BOOST_REQUIRE(roots.has_value());
        retained_roots = *roots;
        background_tip->pqPaymentProbationStateHash =
            saved_background_root;
        snapshot_tip->pqPaymentProbationStateHash = saved_snapshot_root;
    }

    BOOST_CHECK_EQUAL(retained_roots.size(), 2U);
    BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                          background_root) != retained_roots.end());
    BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                          snapshot_root) != retained_roots.end());
    {
        LOCK(::cs_main);
        const uint256 saved_marker{snapshot.CoinsTip().GetBestBlock()};
        const uint256 unknown_marker{non_null_hash(250)};
        BOOST_REQUIRE(
            chainman.m_blockman.LookupBlockIndex(unknown_marker) == nullptr);
        snapshot.CoinsTip().SetBestBlock(unknown_marker);
        BOOST_CHECK(!llmq::CollectChainstatePaymentProbationRoots(chainman)
                         .has_value());
        snapshot.CoinsTip().SetBestBlock(saved_marker);
    }
    llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = 5;
    checkpoint.covered_through_height = 2'000;
    checkpoint.covered_through_hash = GetRandHash();
    checkpoint.authenticated_probation_state_hash = GetRandHash();
    checkpoint.authorizing_target_height = 2'010;
    checkpoint.authorizing_target_hash = GetRandHash();
    checkpoint.authorizing_chainlock_logical_id = GetRandHash();
    checkpoint.authorizing_chainlock_witness_id = GetRandHash();
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    BOOST_REQUIRE(probation_db.PruneStatesThroughCheckpoint(
        checkpoint, retained_roots));

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

// SYSCOIN BEGIN: PQ finality and payment-audit chainstate-manager regressions.
BOOST_FIXTURE_TEST_CASE(
    chainlock_conflict_quarantines_known_header_descendants,
    TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    CBlockHeader rejected_child;

    {
        LOCK(::cs_main);
        CBlockIndex* const active_tip{chainstate.m_chain.Tip()};
        BOOST_REQUIRE(active_tip != nullptr);

        const auto make_header = [](const CBlockIndex& parent,
                                    uint32_t time_offset) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = parent.GetBlockHash();
            header.hashMerkleRoot = GetRandHash();
            header.nTime = parent.nTime + time_offset;
            header.nBits = parent.nBits;
            return header;
        };
        const auto add_header = [&](const CBlockIndex& parent,
                                    uint32_t time_offset)
            EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            const CBlockHeader header{make_header(parent, time_offset)};
            return chainman.m_blockman.AddToBlockIndex(
                header, chainman.m_best_header);
        };

        CBlockIndex* const surviving_1{add_header(*active_tip, 1)};
        CBlockIndex* const surviving_tip{add_header(*surviving_1, 1)};
        CBlockIndex* const conflict_root{add_header(*active_tip, 2)};
        CBlockIndex* const conflict_descendant{
            add_header(*conflict_root, 1)};
        CBlockIndex* const former_best_header{
            add_header(*conflict_descendant, 1)};
        BOOST_REQUIRE_EQUAL(chainman.m_best_header, former_best_header);
        BOOST_REQUIRE(node::CBlockIndexWorkComparator()(
            surviving_tip, former_best_header));

        for (CBlockIndex* index :
             {conflict_root, conflict_descendant, former_best_header}) {
            chainstate.setBlockIndexCandidates.insert(index);
        }
        chainstate.ResetChainLockConflictMarkingStatsForTesting();

        BlockValidationState conflict_state;
        BOOST_REQUIRE(
            chainstate.MarkConflictingBlock(conflict_state, conflict_root));

        for (CBlockIndex* index :
             {conflict_root, conflict_descendant, former_best_header}) {
            BOOST_CHECK(index->nStatus & BLOCK_CONFLICT_CHAINLOCK);
            BOOST_CHECK_EQUAL(
                chainstate.setBlockIndexCandidates.count(index), 0U);
        }
        BOOST_CHECK_EQUAL(chainman.m_best_header, surviving_tip);
        const auto stats{
            chainstate.GetChainLockConflictMarkingStatsForTesting()};
        BOOST_CHECK_EQUAL(stats.batch_calls, 1U);
        BOOST_CHECK_EQUAL(stats.input_roots, 1U);
        BOOST_CHECK_EQUAL(stats.visited_blocks, 3U);
        BOOST_CHECK_EQUAL(stats.block_index_scans, 1U);
        BOOST_CHECK_EQUAL(stats.disconnect_tip_calls, 0U);
        BOOST_CHECK_EQUAL(stats.tip_publications, 1U);

        rejected_child = make_header(*former_best_header, 1);
    }

    while (!CheckProofOfWork(rejected_child.GetHash(), rejected_child.nBits,
                             chainman.GetConsensus())) {
        ++rejected_child.nNonce;
        BOOST_REQUIRE(rejected_child.nNonce != 0);
    }
    const uint256 rejected_hash{rejected_child.GetHash()};
    const CBlockIndex* rejected_index{nullptr};
    BlockValidationState rejected_state;
    BOOST_CHECK(!chainman.ProcessNewBlockHeaders(
        {rejected_child}, /*min_pow_checked=*/true, rejected_state,
        &rejected_index));
    BOOST_CHECK(rejected_state.GetResult() ==
                BlockValidationResult::BLOCK_MISSING_PREV);
    BOOST_CHECK_EQUAL(rejected_state.GetRejectReason(),
                      "bad-prevblk-chainlock");
    BOOST_CHECK(rejected_index == nullptr);
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(rejected_hash) ==
                    nullptr);
    }
    SyncWithValidationInterfaceQueue();
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
    known_payment_receipt.subject_roster_beacon.state =
        llmq::pq::RosterBeaconState::READY;
    known_payment_receipt.subject_roster_beacon.epoch =
        known_payment_receipt.epoch;
    known_payment_receipt.subject_roster_beacon.anchor_cursor =
        llmq::pq::BTCCursor{1, GetRandHash(), GetRandHash()};
    known_payment_receipt.subject_roster_beacon.anchor_btc_height = 1;
    known_payment_receipt.subject_roster_beacon.future_btc_hash =
        GetRandHash();
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

// SYSCOIN END: PQ finality and payment-audit chainstate-manager regressions.

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

// SYSCOIN BEGIN: Durable ChainLock restart and deep-invalidation tests.
// must protect active and side branches across block-index reloads.
BOOST_FIXTURE_TEST_CASE(
    chainlock_conflicting_best_header_is_not_restored_after_restart,
    SnapshotTestSetup)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    uint256 surviving_tip_hash;
    uint256 conflict_root_hash;
    uint256 conflict_tip_hash;

    {
        LOCK(::cs_main);
        CBlockIndex* const active_tip{chainstate.m_chain.Tip()};
        BOOST_REQUIRE(active_tip != nullptr);

        const auto add_header = [&](const CBlockIndex& parent,
                                    uint32_t time_offset)
            EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            CBlockHeader header;
            header.nVersion = 4;
            header.hashPrevBlock = parent.GetBlockHash();
            header.hashMerkleRoot = GetRandHash();
            header.nTime = parent.nTime + time_offset;
            header.nBits = parent.nBits;
            return chainman.m_blockman.AddToBlockIndex(
                header, chainman.m_best_header);
        };

        CBlockIndex* const surviving_1{add_header(*active_tip, 1)};
        CBlockIndex* const surviving_tip{add_header(*surviving_1, 1)};
        CBlockIndex* const conflict_root{add_header(*active_tip, 2)};
        CBlockIndex* const conflict_1{add_header(*conflict_root, 1)};
        CBlockIndex* const conflict_tip{add_header(*conflict_1, 1)};
        BOOST_REQUIRE_EQUAL(chainman.m_best_header, conflict_tip);
        BOOST_REQUIRE(node::CBlockIndexWorkComparator()(
            surviving_tip, conflict_tip));

        BlockValidationState state;
        BOOST_REQUIRE(
            chainstate.MarkConflictingBlock(state, conflict_root));
        BOOST_REQUIRE_EQUAL(chainman.m_best_header, surviving_tip);

        surviving_tip_hash = surviving_tip->GetBlockHash();
        conflict_root_hash = conflict_root->GetBlockHash();
        conflict_tip_hash = conflict_tip->GetBlockHash();
    }

    ChainstateManager& restarted{this->SimulateNodeRestart()};
    this->LoadVerifyActivateChainstate();

    {
        LOCK(::cs_main);
        const CBlockIndex* const surviving_tip{
            restarted.m_blockman.LookupBlockIndex(surviving_tip_hash)};
        const CBlockIndex* const conflict_root{
            restarted.m_blockman.LookupBlockIndex(conflict_root_hash)};
        const CBlockIndex* const conflict_tip{
            restarted.m_blockman.LookupBlockIndex(conflict_tip_hash)};
        BOOST_REQUIRE(surviving_tip != nullptr);
        BOOST_REQUIRE(conflict_root != nullptr);
        BOOST_REQUIRE(conflict_tip != nullptr);
        BOOST_CHECK(conflict_root->nStatus & BLOCK_CONFLICT_CHAINLOCK);
        BOOST_CHECK(conflict_tip->nStatus & BLOCK_CONFLICT_CHAINLOCK);
        BOOST_REQUIRE(restarted.m_best_header != nullptr);
        BOOST_CHECK_EQUAL(restarted.m_best_header->GetBlockHash(),
                          surviving_tip_hash);
    }
}

static CDeterministicMNCPtr MakeDeepRollbackMN(
    int base_height, const uint256& confirmed_hash)
{
    auto member{std::make_shared<CDeterministicMN>(0)};
    member->proTxHash = GetRandHash();
    member->collateralOutpoint = COutPoint{GetRandHash(), 0};

    CKey owner_key;
    CKey voting_key;
    CKey payout_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    voting_key.MakeNewKey(/*fCompressed=*/true);
    payout_key.MakeNewKey(/*fCompressed=*/true);

    auto state{std::make_shared<CDeterministicMNState>()};
    state->nVersion = CProRegTx::LEGACY_BLS_VERSION;
    state->nRegisteredHeight = base_height - 10;
    state->nCollateralHeight = base_height - 20;
    state->keyIDOwner = owner_key.GetPubKey().GetID();
    state->keyIDVoting = voting_key.GetPubKey().GetID();
    state->addr = LookupNumeric("1.2.3.4", 20'001);
    state->scriptPayout =
        GetScriptForDestination(PKHash(payout_key.GetPubKey()));
    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key;
    operator_key.fill(1);
    BOOST_REQUIRE(state->pubKeyOperator.SetBytes(operator_key));
    state->UpdateConfirmedHash(member->proTxHash, confirmed_hash);
    // Keep the fixture out of regtest's reward/seniority schedule. The list is
    // still non-empty and its complete banned state participates in every root.
    state->BanIfNotBanned(base_height);
    member->pdmnState = std::move(state);
    return member;
}

BOOST_FIXTURE_TEST_CASE(
    deep_invalidate_reconstructs_dmn_and_pq_roots_after_restart,
    SnapshotTestSetup)
{
    auto& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreConsensus {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t registration_cutoff{
            consensus.nPQRegistrationCutoffBlocks};
        uint32_t future_horizon{consensus.nPQFutureHorizonEpochs};
        int btcc_candidate_origin{consensus.nPQBTCCCandidateOrigin};
        int btcc_injection_lag{consensus.nPQBTCCNEVMInjectionLag};
        int activation_height{consensus.nPQActivationHeight};
        int receipt_anchor_height{consensus.nPQBTCCReceiptAnchorHeight};
        uint256 receipt_anchor_block{consensus.hashPQBTCCReceiptAnchorBlock};
        int receipt_anchor_cursor_height{
            consensus.nPQBTCCReceiptAnchorCursorHeight};
        uint256 receipt_anchor_cursor_sys{
            consensus.hashPQBTCCReceiptAnchorCursorSysBlock};
        uint256 receipt_anchor_cursor_btc{
            consensus.hashPQBTCCReceiptAnchorCursorBTCBlock};
        uint256 receipt_anchor_state{consensus.hashPQBTCCReceiptAnchorState};
        int receipt_anchor_latest_target{
            consensus.nPQBTCCReceiptAnchorLatestTargetHeight};
        int receipt_anchor_latest_carrier{
            consensus.nPQBTCCReceiptAnchorLatestCarrierHeight};
        ~RestoreConsensus()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = registration_cutoff;
            consensus.nPQFutureHorizonEpochs = future_horizon;
            consensus.nPQBTCCCandidateOrigin = btcc_candidate_origin;
            consensus.nPQBTCCNEVMInjectionLag = btcc_injection_lag;
            consensus.nPQActivationHeight = activation_height;
            consensus.nPQBTCCReceiptAnchorHeight = receipt_anchor_height;
            consensus.hashPQBTCCReceiptAnchorBlock = receipt_anchor_block;
            consensus.nPQBTCCReceiptAnchorCursorHeight =
                receipt_anchor_cursor_height;
            consensus.hashPQBTCCReceiptAnchorCursorSysBlock =
                receipt_anchor_cursor_sys;
            consensus.hashPQBTCCReceiptAnchorCursorBTCBlock =
                receipt_anchor_cursor_btc;
            consensus.hashPQBTCCReceiptAnchorState = receipt_anchor_state;
            consensus.nPQBTCCReceiptAnchorLatestTargetHeight =
                receipt_anchor_latest_target;
            consensus.nPQBTCCReceiptAnchorLatestCarrierHeight =
                receipt_anchor_latest_carrier;
        }
    } restore{consensus};

    CBlockIndex* seeded_base;
    {
        LOCK(::cs_main);
        seeded_base = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    BOOST_REQUIRE(seeded_base != nullptr);
    const int seeded_height{seeded_base->nHeight};
    consensus.DIP0003Height = seeded_height;
    consensus.nPQPreparationHeight = seeded_height + 1;
    // Keep all PQ finality and receipt carriers above this test's tip while
    // retaining a real, valid registry/payment-root deployment.
    consensus.nPQChainLockEpochOrigin = 2'880;
    consensus.nPQRegistrationCutoffBlocks = 531;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQBTCCCandidateOrigin = std::numeric_limits<int>::max();
    consensus.nPQBTCCNEVMInjectionLag = 10;
    consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    consensus.nPQBTCCReceiptAnchorHeight =
        std::numeric_limits<int>::max();
    consensus.hashPQBTCCReceiptAnchorBlock.SetNull();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nPQBTCCReceiptAnchorLatestTargetHeight = -1;
    consensus.nPQBTCCReceiptAnchorLatestCarrierHeight = -1;

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(
        llmq::pq::GetPQRegistryConfig(consensus, registry_config) ==
        llmq::pq::PQRegistryDeploymentResult::VALID);

    const auto member{
        MakeDeepRollbackMN(seeded_height, seeded_base->GetBlockHash())};
    const uint256 pro_tx_hash{member->proTxHash};
    CDeterministicMNList seeded_list{
        seeded_base->GetBlockHash(), seeded_height, 1};
    seeded_list.AddMN(member, /*fBumpTotalCount=*/false);
    BOOST_REQUIRE(deterministicMNManager->m_evoDb->WriteThrough(
        seeded_base->GetBlockHash(), seeded_list, /*fSync=*/true));

    // First create the historical receipt-assumption boundary. The receipt
    // schedule stays disabled until this exact block hash is known.
    mineBlocks(1);
    CBlockIndex* receipt_anchor;
    {
        LOCK(::cs_main);
        receipt_anchor = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    BOOST_REQUIRE(receipt_anchor != nullptr);
    BOOST_REQUIRE_EQUAL(receipt_anchor->nHeight, seeded_height + 1);
    std::string registry_error;

    consensus.nPQActivationHeight = 3'745;
    consensus.nPQBTCCReceiptAnchorHeight = receipt_anchor->nHeight;
    consensus.hashPQBTCCReceiptAnchorBlock =
        receipt_anchor->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nPQBTCCReceiptAnchorLatestTargetHeight = -1;
    consensus.nPQBTCCReceiptAnchorLatestCarrierHeight = -1;
    // No carrier is reached by this test. Enabling the valid schedule still
    // makes ordinary block connection commit the canonical probation root.
    consensus.nPQBTCCCandidateOrigin = 3'745;
    BOOST_REQUIRE(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    mineBlocks(1);
    CBlockIndex* rollback_base;
    {
        LOCK(::cs_main);
        rollback_base = Assert(m_node.chainman)->ActiveChain().Tip();
    }
    BOOST_REQUIRE(rollback_base != nullptr);
    BOOST_REQUIRE_EQUAL(rollback_base->nHeight, seeded_height + 2);
    const int rollback_base_height{rollback_base->nHeight};
    const uint256 rollback_base_hash{rollback_base->GetBlockHash()};
    const auto rollback_base_list{
        deterministicMNManager->GetListForBlock(rollback_base)};
    BOOST_REQUIRE_EQUAL(rollback_base_list.GetAllMNsCount(), 1U);
    BOOST_REQUIRE(rollback_base_list.IsMNPoSeBanned(pro_tx_hash));
    const uint256 expected_dmn_snapshot_hash{
        ::SerializeHash(rollback_base_list)};

    llmq::pq::PQRegistrySnapshot rollback_base_registry;
    registry_error.clear();
    BOOST_REQUIRE(deterministicMNManager->GetPQRegistrySnapshot(
        rollback_base, rollback_base_registry, registry_error));
    const uint256 expected_registry_root{
        rollback_base_registry.consensus_state_root};
    BOOST_REQUIRE(!expected_registry_root.IsNull());

    const uint256 expected_probation_root{
        rollback_base->pqPaymentProbationStateHash};
    BOOST_REQUIRE(!expected_probation_root.IsNull());
    llmq::pq::PQPaymentProbationStateView expected_probation;
    BOOST_REQUIRE(deterministicMNManager->GetPaymentProbationStateView(
        rollback_base, expected_probation));
    BOOST_REQUIRE(expected_probation.State());
    BOOST_CHECK(*expected_probation.State() ==
                llmq::pq::PQPaymentProbationState{});

    constexpr int extra_depth{
        CDeterministicMNManager::LIST_CACHE_SIZE + 2};
    for (int mined{0}; mined < extra_depth; ++mined) {
        try {
            mineBlocks(1);
        } catch (const std::exception& exception) {
            BOOST_FAIL("mining height "
                       << rollback_base_height + mined + 1
                       << " failed: " << exception.what());
        }
    }

    CBlockIndex* pre_restart_tip;
    {
        LOCK(::cs_main);
        auto& active{Assert(m_node.chainman)->ActiveChainstate()};
        BlockValidationState flush_state;
        BOOST_REQUIRE_MESSAGE(
            active.FlushStateToDisk(flush_state, FlushStateMode::ALWAYS),
            flush_state.ToString());
        pre_restart_tip = active.m_chain.Tip();
    }
    BOOST_REQUIRE(pre_restart_tip != nullptr);
    BOOST_REQUIRE_EQUAL(pre_restart_tip->nHeight,
                        rollback_base_height + extra_depth);
    BOOST_CHECK(!deterministicMNManager->VerifyPersistedSnapshot(
        rollback_base));
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedSnapshot(
        pre_restart_tip));
    BOOST_REQUIRE(deterministicMNManager->VerifyInverseJournalTipSeal(
        pre_restart_tip));
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedPQRegistrySnapshot(
        pre_restart_tip));

    SimulateNodeRestart();
    LoadVerifyActivateChainstate();

    ChainstateManager& restarted{*Assert(m_node.chainman)};
    CBlockIndex* invalidate_target;
    CBlockIndex* restarted_tip;
    {
        LOCK(::cs_main);
        restarted_tip = restarted.ActiveChain().Tip();
        invalidate_target =
            restarted.ActiveChain()[rollback_base_height + 1];
    }
    BOOST_REQUIRE(restarted_tip != nullptr);
    BOOST_REQUIRE(invalidate_target != nullptr);
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedSnapshot(
        restarted_tip));
    BOOST_REQUIRE(deterministicMNManager->VerifyInverseJournalTipSeal(
        restarted_tip));
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedPQRegistrySnapshot(
        restarted_tip));

    BlockValidationState invalidate_state;
    BOOST_REQUIRE_MESSAGE(
        restarted.ActiveChainstate().InvalidateBlock(
            invalidate_state, invalidate_target,
            /*bReverify=*/false, /*bUpdateSpecialTxState=*/true),
        invalidate_state.ToString());

    CBlockIndex* recovered_base;
    {
        LOCK(::cs_main);
        recovered_base = restarted.ActiveChain().Tip();
    }
    BOOST_REQUIRE(recovered_base != nullptr);
    BOOST_CHECK_EQUAL(recovered_base->nHeight, rollback_base_height);
    BOOST_CHECK(recovered_base->GetBlockHash() == rollback_base_hash);

    const auto recovered_list{
        deterministicMNManager->GetListForBlock(recovered_base)};
    BOOST_CHECK_EQUAL(recovered_list.GetAllMNsCount(), 1U);
    BOOST_REQUIRE(recovered_list.GetMN(pro_tx_hash));
    BOOST_CHECK(recovered_list.IsMNPoSeBanned(pro_tx_hash));
    BOOST_CHECK(::SerializeHash(recovered_list) ==
                expected_dmn_snapshot_hash);

    llmq::pq::PQRegistrySnapshot recovered_registry;
    registry_error.clear();
    BOOST_REQUIRE(deterministicMNManager->GetPQRegistrySnapshot(
        recovered_base, recovered_registry, registry_error));
    BOOST_CHECK(recovered_registry.consensus_state_root ==
                expected_registry_root);
    BOOST_CHECK(recovered_base->pqPaymentProbationStateHash ==
                expected_probation_root);
    llmq::pq::PQPaymentProbationStateView recovered_probation;
    BOOST_REQUIRE(deterministicMNManager->GetPaymentProbationStateView(
        recovered_base, recovered_probation));
    BOOST_REQUIRE(recovered_probation.State());
    BOOST_CHECK(*recovered_probation.State() ==
                *expected_probation.State());
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedSnapshot(
        recovered_base));
    BOOST_REQUIRE(deterministicMNManager->VerifyPersistedPQRegistrySnapshot(
        recovered_base));
}

// A fsynced side-branch winner protects both its own ancestry and the active
// recovery fork before Start() has imported it into the in-memory store.
BOOST_FIXTURE_TEST_CASE(
    invalidate_rejects_preimport_durable_side_branch_boundary,
    TestChain100Setup)
{
    auto& chainman{static_cast<TestChainstateManager&>(
        *Assert(m_node.chainman))};
    auto& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreConsensus {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t registration_cutoff{
            consensus.nPQRegistrationCutoffBlocks};
        int roster_snapshot_lag{consensus.nPQRosterSnapshotLag};
        uint32_t future_horizon{consensus.nPQFutureHorizonEpochs};
        int btcc_candidate_origin{consensus.nPQBTCCCandidateOrigin};
        int btcc_injection_lag{consensus.nPQBTCCNEVMInjectionLag};
        int activation_height{consensus.nPQActivationHeight};
        int receipt_anchor_height{consensus.nPQBTCCReceiptAnchorHeight};
        uint256 receipt_anchor_block{consensus.hashPQBTCCReceiptAnchorBlock};
        int receipt_anchor_cursor_height{
            consensus.nPQBTCCReceiptAnchorCursorHeight};
        uint256 receipt_anchor_cursor_sys{
            consensus.hashPQBTCCReceiptAnchorCursorSysBlock};
        uint256 receipt_anchor_cursor_btc{
            consensus.hashPQBTCCReceiptAnchorCursorBTCBlock};
        uint256 receipt_anchor_state{consensus.hashPQBTCCReceiptAnchorState};
        int receipt_anchor_latest_target{
            consensus.nPQBTCCReceiptAnchorLatestTargetHeight};
        int receipt_anchor_latest_carrier{
            consensus.nPQBTCCReceiptAnchorLatestCarrierHeight};
        ~RestoreConsensus()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = registration_cutoff;
            consensus.nPQRosterSnapshotLag = roster_snapshot_lag;
            consensus.nPQFutureHorizonEpochs = future_horizon;
            consensus.nPQBTCCCandidateOrigin = btcc_candidate_origin;
            consensus.nPQBTCCNEVMInjectionLag = btcc_injection_lag;
            consensus.nPQActivationHeight = activation_height;
            consensus.nPQBTCCReceiptAnchorHeight = receipt_anchor_height;
            consensus.hashPQBTCCReceiptAnchorBlock = receipt_anchor_block;
            consensus.nPQBTCCReceiptAnchorCursorHeight =
                receipt_anchor_cursor_height;
            consensus.hashPQBTCCReceiptAnchorCursorSysBlock =
                receipt_anchor_cursor_sys;
            consensus.hashPQBTCCReceiptAnchorCursorBTCBlock =
                receipt_anchor_cursor_btc;
            consensus.hashPQBTCCReceiptAnchorState = receipt_anchor_state;
            consensus.nPQBTCCReceiptAnchorLatestTargetHeight =
                receipt_anchor_latest_target;
            consensus.nPQBTCCReceiptAnchorLatestCarrierHeight =
                receipt_anchor_latest_carrier;
        }
    } restore{consensus};

    CBlockIndex* active_tip;
    CBlockIndex* active_lca;
    {
        LOCK(::cs_main);
        active_tip = chainman.ActiveTip();
        BOOST_REQUIRE(active_tip != nullptr);
        BOOST_REQUIRE(active_tip->nHeight > 10);
        active_lca = chainman.ActiveChain()[active_tip->nHeight - 10];
    }
    BOOST_REQUIRE(active_lca != nullptr);

    consensus.DIP0003Height = 1;
    consensus.nPQPreparationHeight = 1;
    consensus.nPQChainLockEpochOrigin = 1'440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQBTCCCandidateOrigin = 2'305;
    consensus.nPQBTCCNEVMInjectionLag =
        static_cast<int>(llmq::pq::PQ_BTCC_NEVM_LAG);
    consensus.nPQActivationHeight = 2'305;
    consensus.nPQBTCCReceiptAnchorHeight = active_lca->nHeight;
    consensus.hashPQBTCCReceiptAnchorBlock = active_lca->GetBlockHash();
    consensus.nPQBTCCReceiptAnchorCursorHeight = -1;
    consensus.hashPQBTCCReceiptAnchorCursorSysBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorCursorBTCBlock.SetNull();
    consensus.hashPQBTCCReceiptAnchorState.SetNull();
    consensus.nPQBTCCReceiptAnchorLatestTargetHeight = -1;
    consensus.nPQBTCCReceiptAnchorLatestCarrierHeight = -1;

    const auto config{
        llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_REQUIRE(llmq::MakePQQuorumBuildConfig(consensus));
    const int32_t target_height{
        config->chainlock_schedule.epoch_origin +
        static_cast<int32_t>(llmq::pq::PQ_FIRST_ELIGIBLE_TARGET_OFFSET)};
    BOOST_REQUIRE(llmq::pq::IsEligibleChainLockTarget(
        config->chainlock_schedule, target_height));

    CBlockIndex* durable_target{active_lca};
    CBlockIndex* durable_ancestor{nullptr};
    CBlockIndex* activation_predecessor{nullptr};
    {
        LOCK(::cs_main);
        for (int32_t height{active_lca->nHeight + 1};
             height <= target_height; ++height) {
            uint256 hash{GetRandHash()};
            while (chainman.m_blockman.LookupBlockIndex(hash) != nullptr) {
                hash = GetRandHash();
            }
            auto [entry, inserted]{
                chainman.m_blockman.m_block_index.try_emplace(hash)};
            BOOST_REQUIRE(inserted);
            CBlockIndex& index{entry->second};
            index.phashBlock = &entry->first;
            index.pprev = durable_target;
            index.nHeight = height;
            index.nChainWork = durable_target->nChainWork + 1;
            index.nTx = 1;
            index.nChainTx = durable_target->nChainTx + 1;
            index.nStatus = BLOCK_VALID_SCRIPTS;
            index.BuildSkip();
            durable_target = &index;
            if (height == config->activation_predecessor_height) {
                activation_predecessor = durable_target;
            }
            if (height == target_height - 1) {
                durable_ancestor = durable_target;
            }
        }
    }
    BOOST_REQUIRE(activation_predecessor != nullptr);
    BOOST_REQUIRE(durable_ancestor != nullptr);
    BOOST_REQUIRE_EQUAL(durable_target->nHeight, target_height);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(durable_target->IsValid(BLOCK_VALID_SCRIPTS));
    }

    llmq::pq::FinalChainLock winner;
    winner.statement.height = durable_target->nHeight;
    winner.statement.block_hash = durable_target->GetBlockHash();
    winner.statement.previous_chainlock_height =
        activation_predecessor->nHeight;
    winner.statement.previous_chainlock_hash =
        activation_predecessor->GetBlockHash();
    winner.statement.quorum_context_hash = GetRandHash();
    winner.statement.roster_transition =
        llmq::pq::RosterAuthorizationTransitionKind::INITIALIZE;
    const auto active_epochs{llmq::pq::ActiveEpochsAtHeight(
        config->chainlock_schedule, winner.statement.height)};
    BOOST_REQUIRE(active_epochs);
    const llmq::pq::BTCCursor recovery_cursor{
        winner.statement.height, winner.statement.block_hash, GetRandHash()};
    uint256 recovery_future_hash{GetRandHash()};
    while (recovery_future_hash == recovery_cursor.btc_hash) {
        recovery_future_hash = GetRandHash();
    }
    for (std::size_t slot{0}; slot < llmq::pq::ACTIVE_QUORUMS; ++slot) {
        auto& seed{winner.statement.roster_beacons.active.seeds[slot]};
        seed.anchor_kind = llmq::pq::RosterBeaconAnchorKind::NORMAL;
        seed.state = llmq::pq::RosterBeaconState::READY;
        seed.epoch = (*active_epochs)[slot].epoch;
        seed.anchor_cursor = recovery_cursor;
        seed.anchor_btc_height = 800'000;
        seed.future_btc_hash = recovery_future_hash;
    }
    winner.statement.roster_beacons.active.recovery_authority_source
        .normal_beacon = winner.statement.roster_beacons.active.seeds.back();
    winner.statement.roster_beacons.next.epoch =
        active_epochs->back().epoch + 1;
    winner.statement.accepted_btcc_cursor = recovery_cursor;
    winner.statement.btcc_advance = llmq::pq::BTCCAdvance::ADVANCE;
    llmq::pq::RosterAuthorizationTransition authorization_transition;
    authorization_transition.kind = winner.statement.roster_transition;
    authorization_transition.target_height = winner.statement.height;
    authorization_transition.target_block_hash = winner.statement.block_hash;
    authorization_transition.predecessor_height =
        winner.statement.previous_chainlock_height;
    authorization_transition.predecessor_block_hash =
        winner.statement.previous_chainlock_hash;
    authorization_transition.new_window = winner.statement.roster_beacons;
    const auto authorization_state_hash{
        llmq::pq::GetRosterAuthorizationStateHash(
            consensus.hashGenesisBlock, authorization_transition)};
    BOOST_REQUIRE(authorization_state_hash);
    winner.statement.roster_authorization_state_hash =
        *authorization_state_hash;
    winner.statement.payment_probation_state_hash = GetRandHash();
    winner.selected_quorum_mask = 0b0111;
    winner.signatures.resize(llmq::pq::FINAL_SIGNATURE_COUNT);
    for (auto& signature : winner.signatures) {
        signature.key_proof.public_key[0] = 1;
    }
    winner.signatures.front().signature.front() = 1;
    for (std::size_t slot{0}; slot < llmq::pq::REQUIRED_QUORUMS; ++slot) {
        for (std::size_t member{0};
             member < llmq::pq::QUORUM_THRESHOLD; ++member) {
            winner.signer_bitmaps[slot][member / 8] |=
                static_cast<uint8_t>(uint8_t{1} << (member % 8));
        }
    }
    BOOST_REQUIRE(winner.IsStructurallyValid());

    // Close the fixture's disabled handler before writing its normal durable
    // database, then reconstruct it without calling Start().
    llmq::StopLLMQSystem();
    llmq::DestroyLLMQSystem();
    chainman.ResetIbd(PQHistoryAuthState::UNINITIALIZED);
    {
        llmq::pq::PQChainLockPersistence persistence{
            DBParams{
                .path = chainman.m_options.datadir /
                    "llmq/pq-chainlocks",
                .cache_bytes = 4U << 20,
                .wipe_data = true,
            },
            consensus.hashGenesisBlock, *config};
        const auto context{
            llmq::pq::ChainLockStoreTestContextFactory::CreateDurable(
                consensus.hashGenesisBlock, config->chainlock_schedule,
                winner.statement)};
        BOOST_REQUIRE(context);
        const auto source_snapshot_height{
            llmq::pq::RegistrationCutoffHeight(
                config->chainlock_schedule,
                winner.statement.roster_beacons.active
                    .recovery_authority_source.normal_beacon.epoch,
                consensus.nPQRosterSnapshotLag)};
        BOOST_REQUIRE(source_snapshot_height);
        const CBlockIndex* source_snapshot{
            durable_target->GetAncestor(*source_snapshot_height)};
        BOOST_REQUIRE(source_snapshot != nullptr);
        const auto recovery_universe{MakeRecoveryUniverseFixture(
            consensus.hashGenesisBlock,
            winner.statement.roster_beacons.active.recovery_authority_source,
            *source_snapshot)};
        BOOST_REQUIRE(recovery_universe);
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            winner, context, /*error=*/nullptr, /*verified_reset=*/nullptr,
            /*payment_audit_seal_context=*/std::nullopt,
            recovery_universe));
    }
    {
        LOCK(::cs_main);
        llmq::InitLLMQSystem(*Assert(m_node.connman),
                             *Assert(m_node.peerman), chainman);
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::PENDING);
    }
    BOOST_REQUIRE(llmq::chainLocksHandler != nullptr);
    BOOST_CHECK(!llmq::chainLocksHandler->GetBestChainLock());

    const CBlockIndex* resolved_floor{nullptr};
    const CBlockIndex* resolved_target{nullptr};
    std::string recovery_error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE_MESSAGE(
            llmq::chainLocksHandler->GetDurableFinalityRecoveryFloor(
                resolved_floor, resolved_target, recovery_error),
            recovery_error);
    }
    BOOST_CHECK_EQUAL(resolved_floor, active_lca);
    BOOST_CHECK_EQUAL(resolved_target, durable_target);

    const auto assert_rejected = [&](CBlockIndex* invalidated) {
        const BlockStatus prior_status{WITH_LOCK(
            ::cs_main, return invalidated->nStatus)};
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(
            !chainman.ActiveChainstate().InvalidateBlock(
                state, invalidated, /*bReverify=*/false,
                /*bUpdateSpecialTxState=*/true),
            "durable finality boundary was invalidated");
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(state.ToString().find(
                        "refusing to invalidate") != std::string::npos);
        LOCK(::cs_main);
        BOOST_CHECK(invalidated->nStatus == prior_status);
        BOOST_CHECK(!(invalidated->nStatus & BLOCK_FAILED_MASK));
        BOOST_CHECK_EQUAL(chainman.ActiveTip(), active_tip);
    };
    assert_rejected(durable_target);
    assert_rejected(durable_ancestor);
    assert_rejected(active_lca);
}
// SYSCOIN END: Durable ChainLock restart and deep-invalidation tests.

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
    // SYSCOIN: Disabled background chainstates remain persistence roots until
    // destruction, preventing sidecar GC from pruning restart-recoverable data.
    Chainstate* background_cs{nullptr};
    {
        LOCK(::cs_main);
        const auto persistence_chainstates{
            chainman.GetAllForPersistence()};
        BOOST_REQUIRE_EQUAL(persistence_chainstates.size(), 2U);
        for (Chainstate* chainstate : persistence_chainstates) {
            if (chainstate != &active_cs) background_cs = chainstate;
        }
    }
    BOOST_REQUIRE(background_cs != nullptr);
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
    {
        LOCK(::cs_main);
        const auto persistence_chainstates{
            chainman.GetAllForPersistence()};
        BOOST_REQUIRE_EQUAL(persistence_chainstates.size(), 2U);
        BOOST_CHECK(std::find(persistence_chainstates.begin(),
                              persistence_chainstates.end(),
                              background_cs) !=
                    persistence_chainstates.end());
    }

    // SYSCOIN: Snapshot completion retains durable and prospective chainstate
    // probation roots before pruning unreferenced states.
    const auto non_null_hash = [](uint8_t tag) {
        uint256 hash;
        hash.begin()[0] = tag;
        return hash;
    };
    const auto make_state = [&](uint32_t epoch, uint8_t tag) {
        llmq::pq::PQPaymentProbationState state;
        state.cursor.has_receipt = 1;
        state.cursor.receipt = {
            epoch, static_cast<int32_t>(3'000 + epoch),
            non_null_hash(tag)};
        state.entries.push_back(
            {non_null_hash(static_cast<uint8_t>(tag + 32)), 1, -1});
        return state;
    };
    auto probation_db_params = DBParams{
        .path = m_path_root / "probation_disabled_chainstate_retention",
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    uint256 durable_root;
    uint256 prospective_root;
    uint256 unreferenced_root;
    {
        llmq::pq::PQPaymentProbationManager probation_db{
            probation_db_params};
        const auto commit = [&](const auto& probation_state) {
            const auto hash{
                llmq::pq::GetPQPaymentProbationStateHash(probation_state)};
            BOOST_REQUIRE(hash.has_value());
            BOOST_REQUIRE(probation_db.CommitState(
                probation_state, *hash, /*fJustCheck=*/false));
            return *hash;
        };
        durable_root = commit(make_state(6, 11));
        prospective_root = commit(make_state(7, 12));
        unreferenced_root = commit(make_state(7, 13));

        std::vector<uint256> retained_roots;
        {
            LOCK(::cs_main);
            const uint256 durable_marker{
                background_cs->CoinsDB().GetBestBlock()};
            BOOST_REQUIRE(!durable_marker.IsNull());
            CBlockIndex* durable_index{
                chainman.m_blockman.LookupBlockIndex(durable_marker)};
            BOOST_REQUIRE(durable_index != nullptr);
            CBlockIndex* prospective_index{
                active_cs.m_chain[durable_index->nHeight + 1]};
            BOOST_REQUIRE(prospective_index != nullptr);

            const uint256 saved_tip_marker{
                background_cs->CoinsTip().GetBestBlock()};
            const uint256 saved_durable_root{
                durable_index->pqPaymentProbationStateHash};
            const uint256 saved_prospective_root{
                prospective_index->pqPaymentProbationStateHash};
            background_cs->CoinsTip().SetBestBlock(
                prospective_index->GetBlockHash());
            durable_index->pqPaymentProbationStateHash = durable_root;
            prospective_index->pqPaymentProbationStateHash =
                prospective_root;

            std::string recovery_error;
            const auto recovery_indexes{
                chainman.GetAllRecoveryBlockIndexes(recovery_error)};
            BOOST_REQUIRE_MESSAGE(recovery_indexes.has_value(),
                                  recovery_error);
            BOOST_CHECK(std::find(recovery_indexes->begin(),
                                  recovery_indexes->end(), durable_index) !=
                        recovery_indexes->end());
            BOOST_CHECK(std::find(recovery_indexes->begin(),
                                  recovery_indexes->end(),
                                  prospective_index) !=
                        recovery_indexes->end());
            const auto roots{
                llmq::CollectChainstatePaymentProbationRoots(chainman)};
            BOOST_REQUIRE(roots.has_value());
            retained_roots = *roots;

            background_cs->CoinsTip().SetBestBlock(saved_tip_marker);
            durable_index->pqPaymentProbationStateHash =
                saved_durable_root;
            prospective_index->pqPaymentProbationStateHash =
                saved_prospective_root;
        }
        BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                              durable_root) != retained_roots.end());
        BOOST_CHECK(std::find(retained_roots.begin(), retained_roots.end(),
                              prospective_root) != retained_roots.end());

        llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
        checkpoint.prune_through_epoch = 7;
        checkpoint.covered_through_height = 4'000;
        checkpoint.covered_through_hash = GetRandHash();
        checkpoint.authenticated_probation_state_hash = GetRandHash();
        checkpoint.authorizing_target_height = 4'010;
        checkpoint.authorizing_target_hash = GetRandHash();
        checkpoint.authorizing_chainlock_logical_id = GetRandHash();
        checkpoint.authorizing_chainlock_witness_id = GetRandHash();
        BOOST_REQUIRE(checkpoint.IsStructurallyValid());
        BOOST_REQUIRE(probation_db.PruneStatesThroughCheckpoint(
            checkpoint, retained_roots));
    }
    probation_db_params.wipe_data = false;
    {
        llmq::pq::PQPaymentProbationManager restarted_probation_db{
            probation_db_params};
        llmq::pq::PQPaymentProbationState loaded;
        BOOST_CHECK(restarted_probation_db.GetState(durable_root, loaded));
        BOOST_CHECK(restarted_probation_db.GetState(prospective_root,
                                                    loaded));
        BOOST_CHECK(!restarted_probation_db.GetState(unreferenced_root,
                                                     loaded));
    }

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
