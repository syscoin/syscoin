// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <addresstype.h> // SYSCOIN: deterministic valid-MN payout.
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/pq_migration_config.h> // SYSCOIN: PQ activation-boundary tests.
#include <consensus/validation.h>
#include <evo/deterministicmns.h> // SYSCOIN: deep rollback integration state.
#include <evo/pq_payment_probation_db.h> // SYSCOIN: multi-chainstate probation GC.
#include <evo/pq_registry.h> // SYSCOIN: deep rollback registry roots.
#include <governance/governance.h> // SYSCOIN: tip-bound block fixture readiness.
#include <kernel/disconnected_transactions.h>
#include <kernel/context.h>
#include <llmq/pq_chainlock_persistence.h> // SYSCOIN: pre-import durable finality.
#include <llmq/pq_chainlock_schedule.h> // SYSCOIN: payment-audit preseal coverage.
#include <llmq/quorums_chainlocks.h> // SYSCOIN: retained probation roots.
#include <llmq/quorums_init.h> // SYSCOIN: recreate pre-import finality handler.
#include <masternode/activemasternode.h>
#include <netbase.h> // SYSCOIN: deterministic valid-MN fixture service.
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/interface_ui.h> // SYSCOIN: startup's genesis notification.
#include <node/kernel_notifications.h>
#include <node/miner.h> // SYSCOIN: preserve NEVM template commitments.
#include <node/utxo_snapshot.h>
#include <pow.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <services/assetconsensus.h> // SYSCOIN: coins-recovery NEVM roots and mint markers.
#include <shutdown.h> // SYSCOIN: managed NEVM shutdown regression.
#include <sync.h>
#include <test/pq_test_util.h> // SYSCOIN: durable roster-context fixture.
#include <test/util/chainstate.h>
#include <test/util/logging.h>
#include <test/util/mining.h>
#include <test/util/nevm_mint.h> // SYSCOIN: fully valid mint block read-error regressions.
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <uint256.h>
#include <undo.h> // SYSCOIN: mint rollback durability fixture.
#include <validation.h>
#include <validationinterface.h>
#include <walletinitinterface.h>

#include <tinyformat.h>

#include <algorithm> // SYSCOIN: synthetic recovery-universe fixture.
#include <array> // SYSCOIN: synthetic PQ activation fixtures.
#include <chrono> // SYSCOIN: bounded crash-test subprocess lifetime.
#include <cstdint> // SYSCOIN: synthetic recovery-authority fixture.
#include <cstdlib> // SYSCOIN: unclean exit of an owned crash-test subprocess.
#include <functional> // SYSCOIN: observe coins/mint persistence ordering.
#include <limits>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <thread> // SYSCOIN: bounded wait for an owned crash-test subprocess.
#include <vector>

#if defined(HAVE_BOOST_PROCESS) || defined(ENABLE_EXTERNAL_SIGNER)
// SYSCOIN: Use a fresh process rather than forking an active chain fixture.
#include <boost/version.hpp>
#if BOOST_VERSION >= 108800
#include <boost/process/v1/args.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/exe.hpp>
#else
#include <boost/process.hpp>
#endif
#endif

#include <boost/signals2/connection.hpp>
#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

namespace llmq::test {
class PQHistoryReauthenticationTestAccess {
public:
    static PQHistoryReauthentication Make(
        const ChainstateManager& owner, const CBlockIndex& old_coverage,
        const CBlockIndex& selected_tip,
        const CBlockIndex* previous_floor, const CBlockIndex* current_floor,
        const uint256& dependency_token, uint64_t old_revision)
    {
        return PQHistoryReauthentication{owner, old_coverage, selected_tip,
            previous_floor, current_floor, dependency_token, old_revision};
    }

    static void RemoveOwner(PQHistoryReauthentication& proof)
    {
        proof.m_owner = nullptr;
    }

    static void ReplaceCoverageHash(PQHistoryReauthentication& proof,
                                    const uint256& hash)
    {
        proof.m_old_coverage.hash = hash;
    }

    static void RevokeProvenance(ChainstateManager& chainman)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        chainman.NotePQProvenanceRevoked();
    }
};
} // namespace llmq::test

namespace {
struct DeferredNEVMReplaySetup : TestChain100Setup {
    explicit DeferredNEVMReplaySetup(bool coins_db_in_memory = true,
                                     bool managed_exit = false)
        : TestChain100Setup{ChainType::REGTEST,
                            managed_exit
                                ? std::vector<const char*>{"-nevmstartheight=101",
                                                          "-gethcommandline=--exitwhensynced"}
                                : std::vector<const char*>{"-nevmstartheight=101"},
                            COINBASE_MATURITY,
                            coins_db_in_memory} {}
};

// SYSCOIN: Exercise Core's real NEVM connection path without an external
// process. Tests may defer application until an explicit flush while still
// acknowledging connects; the default preserves immediate application.
// Template checks leave its applied pair unchanged.
struct StartupNEVMSubscriber final : CValidationInterface {
    struct AppliedPair {
        uint64_t count;
        uint256 hash;
    };

    uint64_t applied_count{0};
    uint256 applied_hash;
    bool buffer_connects{false};
    bool flush_available{true};
    std::optional<AppliedPair> buffered_pair;
    std::optional<AppliedPair> reported_pair_override;
    std::optional<AppliedPair> last_reported_pair;
    std::size_t flush_requests{0};
    bool status_available{true};
    std::size_t status_requests{0};
    std::string block_info_error;
    std::string connect_error;
    std::string disconnect_error;
    std::size_t block_info_queries{0};
    std::vector<uint256> connected_blocks;
    std::vector<uint256> disconnected_blocks;
    uint8_t template_serial{0};
    std::optional<uint256> template_block_hash;
    std::optional<NEVMTxRoot> template_roots;

    void NotifyGetNEVMBlock(CNEVMBlock& block, std::string& state) override
    {
        state.clear();
        block.nBlockHash.begin()[0] = ++template_serial;
        block.nTxRoot = block.nBlockHash;
        block.nReceiptRoot = block.nBlockHash;
        if (template_block_hash) block.nBlockHash = *template_block_hash;
        if (template_roots) {
            block.nTxRoot = template_roots->nTxRoot;
            block.nReceiptRoot = template_roots->nReceiptRoot;
        }
        // Core treats this payload as opaque; the subscriber substitutes for
        // the external engine that produces and validates it.
        block.vchNEVMBlockData = {template_serial};
    }

    void NotifyNEVMBlockConnect(
        const CNEVMHeader&, const CBlock&, std::string& state,
        const uint256& hash, NEVMDataVec&, const uint32_t& height,
        bool, const uint256&,
        const CDeterministicMNListNEVMAddressDiff&) override
    {
        state.clear();
        if (hash.IsNull()) return;
        connected_blocks.push_back(hash);
        if (!connect_error.empty()) {
            state = connect_error;
            return;
        }
        if (buffer_connects) {
            buffered_pair = AppliedPair{height - 101 + 1, hash};
            return;
        }
        applied_count = height - 101 + 1;
        applied_hash = hash;
    }

    void NotifyNEVMComms(const std::string& command, bool& response) override
    {
        if (command == "status") {
            ++status_requests;
            response = status_available;
            return;
        }
        if (command != "flush") return;
        ++flush_requests;
        response = flush_available;
        if (!response) return;
        if (buffered_pair) {
            applied_count = buffered_pair->count;
            applied_hash = buffered_pair->hash;
            buffered_pair.reset();
        }
    }

    void NotifyNEVMBlockDisconnect(
        std::string& state, const uint256& hash,
        const CDeterministicMNListNEVMAddressDiff&) override
    {
        state.clear();
        disconnected_blocks.push_back(hash);
        state = disconnect_error;
    }

    void NotifyGetNEVMBlockInfo(
        uint64_t& count, uint256& hash, std::string& state) override
    {
        ++block_info_queries;
        const auto reported{reported_pair_override.value_or(
            AppliedPair{applied_count, applied_hash})};
        count = reported.count;
        hash = reported.hash;
        state = block_info_error;
        if (state.empty()) {
            last_reported_pair = AppliedPair{count, hash};
        }
    }
};

struct StartupNEVMRecoverySetup : DeferredNEVMReplaySetup {
    const bool previous_nevm_connection{fNEVMConnection};
    std::shared_ptr<StartupNEVMSubscriber> nevm{
        std::make_shared<StartupNEVMSubscriber>()};

    explicit StartupNEVMRecoverySetup(bool coins_db_in_memory = true,
                                      bool managed_exit = false)
        : DeferredNEVMReplaySetup{coins_db_in_memory, managed_exit}
    {
        RegisterSharedValidationInterface(nevm);
        fNEVMConnection = true;
    }

    ~StartupNEVMRecoverySetup()
    {
        UnregisterValidationInterface(nevm.get());
        SyncWithValidationInterfaceQueue();
        fNEVMConnection = previous_nevm_connection;
    }

    std::shared_ptr<const CBlock> MakeNEVMBlock()
    {
        auto& chainman{*Assert(m_node.chainman)};
        CBlock block{node::BlockAssembler{
            chainman.ActiveChainstate(), nullptr}
                         .CreateNewBlock(CScript{} << OP_TRUE)->block};
        block.hashMerkleRoot = BlockMerkleRoot(block);
        while (!CheckProofOfWork(
            block.GetHash(), block.nBits, chainman.GetConsensus())) {
            ++block.nNonce;
        }
        return std::make_shared<const CBlock>(std::move(block));
    }

    std::shared_ptr<const CBlock> MineNEVMBlock(bool forward_to_nevm = true)
    {
        const auto block{MakeNEVMBlock()};
        auto& chainman{*Assert(m_node.chainman)};
        {
            struct RestoreNEVMConnection {
                const bool previous{fNEVMConnection};
                ~RestoreNEVMConnection() { fNEVMConnection = previous; }
            } restore;
            // Keep the valid template's NEVM payload in the stored block,
            // while preparing a Core prefix awaiting external delivery.
            if (!forward_to_nevm) fNEVMConnection = false;
            BOOST_REQUIRE(chainman.ProcessNewBlock(block, true, true, nullptr));
        }
        BOOST_REQUIRE(WITH_LOCK(
            ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                      block->GetHash());
        SetMockTime(GetTime() + 1);
        return block;
    }

    void CheckConnectError(const std::string& error, bool engine_rejection = false,
                           bool managed_exit = false)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        BOOST_REQUIRE(pnevmtxrootsdb != nullptr);
        const auto candidate{MakeNEVMBlock()};
        const COutPoint candidate_coinbase{candidate->vtx.front()->GetHash(), 0};
        const COutPoint existing_coin{m_coinbase_txns.front()->GetHash(), 0};
        CNEVMHeader header;
        BlockValidationState header_state;
        BOOST_REQUIRE(GetNEVMData(header_state, *candidate, header));
        CBlockIndex* candidate_index{nullptr};
        CBlockIndex* original_tip{nullptr};
        uint256 durable_tip;
        {
            LOCK(::cs_main);
            original_tip = chainman.ActiveTip();
            durable_tip = chainstate.CoinsDB().GetBestBlock();
            // Validate the complete candidate before injecting a notifier error.
            BlockValidationState valid_state;
            BOOST_REQUIRE_MESSAGE(TestBlockValidity(
                valid_state, chainman.GetParams(), chainstate, *candidate,
                original_tip, chainman.m_options.adjusted_time_callback),
                valid_state.ToString());
            BlockValidationState accept_state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                candidate, accept_state, &candidate_index, /*fRequested=*/true,
                /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
                accept_state.ToString());
            BOOST_REQUIRE(candidate_index != nullptr);
            BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), 1U);
            BOOST_REQUIRE(chainstate.CoinsTip().HaveCoin(existing_coin));
        }
        CBlockHeader descendant{candidate->GetBlockHeader()};
        descendant.hashPrevBlock = candidate->GetHash();
        ++descendant.nTime;
        descendant.nNonce = 0;
        while (!CheckProofOfWork(descendant.GetHash(), descendant.nBits,
                                 chainman.GetConsensus())) ++descendant.nNonce;
        BlockValidationState descendant_state;
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {descendant}, /*min_pow_checked=*/true, descendant_state),
            descendant_state.ToString());
        CBlockIndex* descendant_index{WITH_LOCK(::cs_main,
            return chainman.m_blockman.LookupBlockIndex(descendant.GetHash()))};
        BOOST_REQUIRE(descendant_index != nullptr);
        const auto connects{nevm->connected_blocks.size()};
        const auto status_queries{nevm->status_requests};
        const auto applied_hash{nevm->applied_hash};
        const auto applied_count{nevm->applied_count};
        // A healthy mock status prevents the send-error path launching Geth.
        nevm->status_available = true;
        nevm->connect_error = error;
        BlockValidationState failed_state;
        const bool activated{chainstate.ActivateBestChain(failed_state, candidate)};
        if (engine_rejection) {
            // ActivateBestChain retires invalid candidates and resets its state.
            BOOST_CHECK(activated);
        } else {
            BOOST_CHECK(!activated);
            BOOST_CHECK(failed_state.IsError());
            BOOST_CHECK(!failed_state.IsInvalid());
            BOOST_CHECK_EQUAL(failed_state.GetRejectReason(), error);
        }
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 1);
        BOOST_CHECK_EQUAL(nevm->status_requests,
                          status_queries + (error == "nevm-connect-not-sent" ? 1U : 0U));
        BOOST_CHECK(nevm->applied_hash == applied_hash);
        BOOST_CHECK_EQUAL(nevm->applied_count, applied_count);
        {
            LOCK(::cs_main);
            BOOST_CHECK(chainman.ActiveTip() == original_tip);
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == original_tip->GetBlockHash());
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_tip);
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(existing_coin));
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(candidate_coinbase));
            BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK,
                              engine_rejection ? BLOCK_FAILED_VALID : 0U);
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index),
                              engine_rejection ? 0U : 1U);
            if (!engine_rejection) {
                BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
            }
        }
        NEVMTxRoot roots;
        BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots));
        BOOST_CHECK(!pnevmtxrootsdb->Read(header.nBlockHash, roots));
        nevm->connect_error.clear();
        if (managed_exit) {
            BOOST_CHECK(ShutdownRequested());
            AbortShutdown();
        }
        if (engine_rejection) return;
        // Retry this exact indexed block without reconsidering its branch.
        BlockValidationState retry_state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(retry_state, candidate),
                              retry_state.ToString());
        BOOST_CHECK(retry_state.IsValid());
        {
            LOCK(::cs_main);
            BOOST_CHECK(chainman.ActiveTip() == candidate_index);
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == candidate->GetHash());
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(candidate_coinbase));
            BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
        }
        BOOST_CHECK(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots));
        BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
        BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
        BOOST_CHECK(nevm->applied_hash == candidate->GetHash());
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 2);
        SetMockTime(GetTime() + 1);
    }

    void RewindCore(int height)
    {
        struct RestoreNEVMConnection {
            const bool previous{fNEVMConnection};
            ~RestoreNEVMConnection() { fNEVMConnection = previous; }
        } restore;
        fNEVMConnection = false;
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK2(::cs_main, chainstate.MempoolMutex());
        while (chainman.ActiveHeight() > height) {
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainstate.DisconnectTip(
                                      state, nullptr, /*bReverify=*/false),
                                  state.ToString());
            // A restart rebuilds candidates above the recovered coins tip.
            // Restore entries pruned while this fixture first mined ahead.
            chainstate.setBlockIndexCandidates.insert(chainman.ActiveTip());
        }
    }

    struct CompetingStartupBranches {
        std::shared_ptr<const CBlock> fork;
        std::shared_ptr<const CBlock> applied;
        std::shared_ptr<const CBlock> sibling;
        std::shared_ptr<const CBlock> sibling_tip;
        CBlockIndex* applied_index{nullptr};
        CBlockIndex* sibling_index{nullptr};
        CBlockIndex* sibling_tip_index{nullptr};
    };

    CompetingStartupBranches PrepareCompetingStartupPair(bool have_applied_body = true)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        CompetingStartupBranches branches;
        branches.fork = MineNEVMBlock();
        branches.applied = MakeNEVMBlock();
        branches.sibling = MineNEVMBlock(/*forward_to_nevm=*/false);
        branches.sibling_tip = MineNEVMBlock(/*forward_to_nevm=*/false);
        BOOST_REQUIRE(branches.applied->GetHash() != branches.sibling->GetHash());
        RewindCore(101);
        BlockValidationState header_state;
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {branches.applied->GetBlockHeader()}, /*min_pow_checked=*/true,
            header_state), header_state.ToString());
        LOCK(::cs_main);
        branches.applied_index = chainman.m_blockman.LookupBlockIndex(branches.applied->GetHash());
        branches.sibling_index = chainman.m_blockman.LookupBlockIndex(branches.sibling->GetHash());
        branches.sibling_tip_index = chainman.m_blockman.LookupBlockIndex(branches.sibling_tip->GetHash());
        BOOST_REQUIRE(branches.applied_index != nullptr);
        BOOST_REQUIRE(branches.sibling_index != nullptr);
        BOOST_REQUIRE(branches.sibling_tip_index != nullptr);
        BOOST_REQUIRE_EQUAL(branches.applied_index->nHeight, 102);
        BOOST_REQUIRE_EQUAL(branches.sibling_tip_index->nHeight, 103);
        BOOST_REQUIRE(branches.applied_index->pprev == chainman.ActiveTip());
        BOOST_REQUIRE(branches.sibling_index->pprev == branches.applied_index->pprev);
        BOOST_REQUIRE(branches.sibling_tip_index->pprev == branches.sibling_index);
        BOOST_REQUIRE(branches.sibling_tip_index->nChainWork > branches.applied_index->nChainWork);
        if (have_applied_body) {
            BlockValidationState accept_state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                branches.applied, accept_state, nullptr, /*fRequested=*/true,
                /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
                accept_state.ToString());
        }
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(branches.applied_index),
                            have_applied_body ? 1U : 0U);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(branches.sibling_tip_index), 1U);
        BOOST_REQUIRE_EQUAL(bool(branches.applied_index->nStatus & BLOCK_HAVE_DATA), have_applied_body);
        BOOST_REQUIRE(branches.sibling_tip_index->nStatus & BLOCK_HAVE_DATA);
        nevm->applied_count = 2;
        nevm->applied_hash = branches.applied->GetHash();
        nevm->connected_blocks.clear();
        nevm->disconnected_blocks.clear();
        std::string error;
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, nevm->applied_hash, error));
        BOOST_REQUIRE(chainman.HasPendingNEVMStartupPair());
        return branches;
    }

    void CheckCompetingStartupPairCompleted(const CompetingStartupBranches& branches)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(nevm->disconnected_blocks == std::vector<uint256>{branches.applied->GetHash()});
        BOOST_CHECK(nevm->connected_blocks ==
                    (std::vector<uint256>{branches.sibling->GetHash(), branches.sibling_tip->GetHash()}));
        BOOST_CHECK_EQUAL(nevm->applied_count, 3U);
        BOOST_CHECK(nevm->applied_hash == branches.sibling_tip->GetHash());
        BOOST_REQUIRE(nevm->last_reported_pair.has_value());
        BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 2U);
        BOOST_CHECK(nevm->last_reported_pair->hash == branches.applied->GetHash());
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == branches.sibling_tip->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == branches.sibling_tip->GetHash());
        BOOST_CHECK_EQUAL(branches.applied_index->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK_EQUAL(branches.sibling_index->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK_EQUAL(branches.sibling_tip_index->nStatus & BLOCK_FAILED_MASK, 0U);
    }

    void CheckCompetingStartupPairQuarantine(bool payment_audit)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        const auto branches{PrepareCompetingStartupPair()};
        const uint256 logical_id{GetRandHash()};
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(payment_audit
                ? chainstate.DeferPaymentAuditReceiptCandidates(logical_id, *branches.applied_index)
                : chainstate.DeferBTCCReceiptCandidates(logical_id, *branches.applied_index));
            BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.applied_index));
            BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
        }
        BlockValidationState waiting_state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(waiting_state), waiting_state.ToString());
        BOOST_CHECK(waiting_state.IsValid());
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(nevm->connected_blocks.empty());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        {
            LOCK(::cs_main);
            BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == branches.fork->GetHash());
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == branches.fork->GetHash());
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(branches.applied_index), 0U);
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(branches.sibling_tip_index), 1U);
            BOOST_REQUIRE(payment_audit
                ? chainstate.ReconsiderPaymentAuditReceiptCandidates(logical_id)
                : chainstate.ReconsiderBTCCReceiptCandidates(logical_id));
            BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*branches.applied_index));
            BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
        }
        BlockValidationState recovery_state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(recovery_state), recovery_state.ToString());
        BOOST_CHECK(recovery_state.IsValid());
        CheckCompetingStartupPairCompleted(branches);
    }
};

struct ManagedNEVMShutdownSetup : StartupNEVMRecoverySetup {
    ManagedNEVMShutdownSetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/true, /*managed_exit=*/true}
    {
        BOOST_REQUIRE(!ShutdownRequested());
    }
    ~ManagedNEVMShutdownSetup() { AbortShutdown(); }
};

// SYSCOIN BEGIN: Mint database read errors must leave block candidates usable.
class NEVMMintReadErrorRootsDB final : public CNEVMTxRootsDB {
public:
    using CNEVMTxRootsDB::CNEVMTxRootsDB;
    std::optional<uint256> failed_hash;
    size_t failures{0};

protected:
    bool ReadTxRootsFromDisk(const uint256& hash, NEVMTxRoot& roots) override
    {
        if (failed_hash == hash) {
            ++failures;
            throw dbwrapper_error("injected NEVM source-root read error");
        }
        return CNEVMTxRootsDB::ReadTxRootsFromDisk(hash, roots);
    }
};

class NEVMMintReadErrorMintDB final : public CNEVMMintedTxDB {
public:
    using CNEVMMintedTxDB::CNEVMMintedTxDB;
    std::optional<uint256> failed_hash;
    size_t failures{0};

protected:
    bool ExistsTxOnDisk(const uint256& hash) override
    {
        if (failed_hash == hash) {
            ++failures;
            throw dbwrapper_error("injected NEVM consumed-proof read error");
        }
        return CNEVMMintedTxDB::ExistsTxOnDisk(hash);
    }
};

struct NEVMMintReadErrorSetup : StartupNEVMRecoverySetup {
    Consensus::Params& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    const int previous_nexus_height{consensus.nNexusStartBlock};
    const bool previous_shutdown_on_fatal_error{
        m_node.notifications->m_shutdown_on_fatal_error};
    std::unique_ptr<CNEVMTxRootsDB> previous_roots_db{std::move(pnevmtxrootsdb)};
    std::unique_ptr<CNEVMMintedTxDB> previous_mint_db{std::move(pnevmtxmintdb)};

    NEVMMintReadErrorSetup()
    {
        // The shared 100-block base predates asset validation. Enable it for
        // the real source/funding block and its mint-containing successor.
        consensus.nNexusStartBlock = 101;
        m_node.notifications->m_shutdown_on_fatal_error = false;
        pnevmtxrootsdb = std::make_unique<NEVMMintReadErrorRootsDB>(DBParams{
            .path = "mint_block_read_error_roots", .cache_bytes = 1U << 20,
            .memory_only = true, .wipe_data = true});
        pnevmtxmintdb = std::make_unique<NEVMMintReadErrorMintDB>(DBParams{
            .path = "mint_block_read_error_markers", .cache_bytes = 1U << 20,
            .memory_only = true, .wipe_data = true});
    }

    ~NEVMMintReadErrorSetup()
    {
        consensus.nNexusStartBlock = previous_nexus_height;
        m_node.notifications->m_shutdown_on_fatal_error =
            previous_shutdown_on_fatal_error;
        m_node.exit_status.store(EXIT_SUCCESS);
        pnevmtxrootsdb = std::move(previous_roots_db);
        pnevmtxmintdb = std::move(previous_mint_db);
    }

    std::shared_ptr<const CBlock> MakeMintBlock(const CMutableTransaction& tx)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto block_template{node::BlockAssembler{
            chainman.ActiveChainstate(), nullptr}.CreateNewBlock(CScript{} << OP_TRUE)};
        CBlock block{block_template->block};
        block.vtx.push_back(MakeTransactionRef(tx));
        // The generic chain fixture discards extra coinbase data. Keep the
        // source roots and NEVM tag while rebuilding the witness commitment.
        node::RegenerateCommitments(block, chainman,
                                    block_template->vchCoinbaseCommitmentExtra);
        block.fChecked = false;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
            ++block.nNonce;
        }
        return std::make_shared<const CBlock>(std::move(block));
    }

    void CheckReadError(bool roots_error)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        auto& roots_db{static_cast<NEVMMintReadErrorRootsDB&>(*pnevmtxrootsdb)};
        auto& mint_db{static_cast<NEVMMintReadErrorMintDB&>(*pnevmtxmintdb)};
        auto valid_mint{MakeValidNEVMMintFixture(
            consensus, 102, WitnessV0KeyHash{coinbaseKey.GetPubKey()},
            uint256S("fa01"))};

        // Commit the actual proof roots in a source block, and give the mint
        // a confirmed non-coinbase OP_TRUE input. Core's mint and input checks
        // remain enabled; the existing subscriber represents the NEVM engine.
        nevm->template_block_hash = valid_mint.mint.nBlockHash;
        nevm->template_roots = NEVMTxRoot{
            valid_mint.mint.nTxRoot, valid_mint.mint.nReceiptRoot};
        const auto funding{CreateValidMempoolTransaction(
            m_coinbase_txns.front(), 0, 1, coinbaseKey,
            CScript{} << OP_TRUE, 10 * COIN, /*submit=*/false)};
        const auto source{MakeMintBlock(funding)};
        {
            LOCK(::cs_main);
            BlockValidationState source_state;
            BOOST_REQUIRE_MESSAGE(TestBlockValidity(
                source_state, chainman.GetParams(), chainstate, *source,
                chainman.ActiveTip(), chainman.m_options.adjusted_time_callback),
                source_state.ToString());
        }
        BOOST_REQUIRE(chainman.ProcessNewBlock(source, true, true, nullptr));
        BOOST_REQUIRE(WITH_LOCK(::cs_main,
            return chainman.ActiveTip()->GetBlockHash()) == source->GetHash());
        nevm->template_block_hash.reset();
        nevm->template_roots.reset();
        SetMockTime(GetTime() + 1);
        BOOST_REQUIRE(roots_db.FlushCacheToDisk());

        const COutPoint funding_output{funding.GetHash(), 0};
        valid_mint.tx.vin.emplace_back(funding_output);
        const auto candidate{MakeMintBlock(valid_mint.tx)};
        const COutPoint minted_output{valid_mint.tx.GetHash(), 0};
        const COutPoint candidate_coinbase{candidate->vtx.front()->GetHash(), 0};
        CNEVMHeader candidate_header;
        BlockValidationState header_state;
        BOOST_REQUIRE(GetNEVMData(header_state, *candidate, candidate_header));

        CBlockIndex* candidate_index{nullptr};
        CBlockIndex* descendant_index{nullptr};
        {
            LOCK(::cs_main);
            // Prove the complete candidate passes before injecting storage
            // failure, including its mint proofs, outputs, and input script.
            BlockValidationState valid_state;
            BOOST_REQUIRE_MESSAGE(TestBlockValidity(
                valid_state, chainman.GetParams(), chainstate, *candidate,
                chainman.ActiveTip(), chainman.m_options.adjusted_time_callback),
                valid_state.ToString());
            BOOST_REQUIRE(valid_state.IsValid());
            BlockValidationState accept_state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                candidate, accept_state, &candidate_index, /*fRequested=*/true,
                /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
                accept_state.ToString());
            BOOST_REQUIRE(candidate_index != nullptr);
            BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), 1U);
        }
        // Retain a known descendant header so a local read fault cannot
        // poison either this candidate or the branch extending it.
        CBlockHeader descendant{candidate->GetBlockHeader()};
        descendant.hashPrevBlock = candidate->GetHash();
        ++descendant.nTime;
        descendant.nNonce = 0;
        while (!CheckProofOfWork(descendant.GetHash(), descendant.nBits, consensus)) {
            ++descendant.nNonce;
        }
        BlockValidationState descendant_state;
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {descendant}, /*min_pow_checked=*/true, descendant_state),
            descendant_state.ToString());
        {
            LOCK(::cs_main);
            descendant_index = chainman.m_blockman.LookupBlockIndex(descendant.GetHash());
            BOOST_REQUIRE(descendant_index != nullptr);
        }

        const auto durable_tip{WITH_LOCK(::cs_main,
            return chainstate.CoinsDB().GetBestBlock())};
        const auto nevm_connects{nevm->connected_blocks.size()};
        if (roots_error) roots_db.failed_hash = valid_mint.mint.nBlockHash;
        else mint_db.failed_hash = valid_mint.mint.nTxHash;
        BlockValidationState failed_state;
        BOOST_CHECK(!chainstate.ActivateBestChain(failed_state, candidate));
        BOOST_CHECK(failed_state.IsError());
        BOOST_CHECK(!failed_state.IsInvalid());
        BOOST_CHECK(failed_state.ToString().find(
            roots_error ? "injected NEVM source-root read error"
                        : "injected NEVM consumed-proof read error") != std::string::npos);
        BOOST_CHECK_EQUAL(roots_error ? roots_db.failures : mint_db.failures, 1U);
        // FatalError must notify the node without poisoning block validity.
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
        roots_db.failed_hash.reset();
        mint_db.failed_hash.reset();
        {
            LOCK(::cs_main);
            BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), 1U);
            BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == source->GetHash());
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == source->GetHash());
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_tip);
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(funding_output));
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(minted_output));
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(candidate_coinbase));
        }
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), nevm_connects);
        BOOST_CHECK(!mint_db.ExistsTx(valid_mint.mint.nTxHash));
        BOOST_CHECK(!mint_db.Exists(valid_mint.mint.nTxHash));
        NEVMTxRoot roots;
        BOOST_CHECK(!roots_db.ReadTxRoots(candidate_header.nBlockHash, roots));
        BOOST_REQUIRE(roots_db.ReadTxRoots(valid_mint.mint.nBlockHash, roots));
        BOOST_CHECK(roots.nTxRoot == valid_mint.mint.nTxRoot);
        BOOST_CHECK(roots.nReceiptRoot == valid_mint.mint.nReceiptRoot);

        // Retry the exact indexed candidate without reconsidering or replacing
        // any block. Restoring storage must be enough for normal activation.
        m_node.exit_status.store(EXIT_SUCCESS);
        BlockValidationState retry_state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(retry_state, candidate),
                              retry_state.ToString());
        BOOST_CHECK(retry_state.IsValid());
        {
            LOCK(::cs_main);
            BOOST_CHECK(chainman.ActiveTip() == candidate_index);
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == candidate->GetHash());
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(funding_output));
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(minted_output));
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(candidate_coinbase));
            BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
        }
        BOOST_CHECK(mint_db.ExistsTx(valid_mint.mint.nTxHash));
        BOOST_CHECK(roots_db.ReadTxRoots(candidate_header.nBlockHash, roots));
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    }
};
// SYSCOIN END: Mint database read errors must leave block candidates usable.

struct CoinsNEVMRecoverySetup : StartupNEVMRecoverySetup {
    Consensus::Params& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    const int previous_dip3_height{consensus.DIP0003Height};
    const int previous_dip3_enforcement{consensus.DIP0003EnforcementHeight};

    CoinsNEVMRecoverySetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/false}
    {
        // BasicTestingSetup force-sets the DIP3 argument. Activate the actual
        // fixture consensus only after its unchanged 100-block base exists.
        consensus.DIP0003Height = 101;
        consensus.DIP0003EnforcementHeight = 101;
    }

    ~CoinsNEVMRecoverySetup()
    {
        consensus.DIP0003Height = previous_dip3_height;
        consensus.DIP0003EnforcementHeight = previous_dip3_enforcement;
    }

    void PrepareInterruptedFlush(const uint256& new_head,
                                 const uint256& old_head)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        const auto path{chainstate.CoinsDB().StoragePath()};
        BOOST_REQUIRE(path.has_value());
        // Drop unflushed cache changes and reopen the real coins store with
        // the exact recovery marker written by an interrupted BatchWrite.
        chainstate.ResetCoinsViews();
        {
            CDBWrapper db{DBParams{
                .path = *path,
                .cache_bytes = 1U << 20,
                .obfuscate = true,
            }};
            CDBBatch batch{db};
            batch.Erase(uint8_t{'B'});
            batch.Write(uint8_t{'H'},
                        std::vector<uint256>{new_head, old_head});
            BOOST_REQUIRE(db.WriteBatch(batch, /*fSync=*/true));
        }
        chainstate.InitCoinsDB(/*cache_size_bytes=*/1U << 20,
                               /*in_memory=*/false,
                               /*should_wipe=*/false);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock().IsNull());
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks() ==
                    (std::vector<uint256>{new_head, old_head}));
    }

    void CheckRecoveredTip(const uint256& expected_hash)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == expected_hash);
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        chainstate.InitCoinsCache(1U << 23);
        BOOST_REQUIRE(chainstate.LoadChainTip());
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == expected_hash);
        const auto recovered_list{
            deterministicMNManager->GetListForBlock(chainman.ActiveTip())};
        BOOST_CHECK(recovered_list.GetBlockHash() == expected_hash);
        BOOST_CHECK_EQUAL(recovered_list.GetHeight(), chainman.ActiveHeight());
    }
};

// SYSCOIN BEGIN: Exercise the production rollback callers with actual coins
// and mint databases. The stored mint is a parsed, previously-validated-state
// bookkeeping fixture; Ethereum proof validation is tested separately.
struct ObservedRollbackMintDB final : CNEVMMintedTxDB {
    using CNEVMMintedTxDB::CNEVMMintedTxDB;
    std::function<void(bool)> before_write;

protected:
    bool WriteCacheBatch(CDBBatch& batch, bool sync) override
    {
        if (before_write) before_write(sync);
        return CDBWrapper::WriteBatch(batch, sync);
    }
};

struct MintRollbackDurabilitySetup : TestChain100Setup {
    std::unique_ptr<CNEVMMintedTxDB> previous_mint_db;
    const uint256 mint_hash{uint256S("b001")};
    COutPoint mint_coin;
    uint256 parent_hash;
    uint256 stored_tip_hash;

    MintRollbackDurabilitySetup()
        : TestChain100Setup{ChainType::REGTEST, {}, COINBASE_MATURITY,
                            /*coins_db_in_memory=*/false},
          previous_mint_db{std::move(pnevmtxmintdb)}
    {
        pnevmtxmintdb = std::make_unique<ObservedRollbackMintDB>(DBParams{
            .path = m_node.chainman->m_options.datadir / "mint-rollback-test",
            .cache_bytes = 1U << 20,
            .wipe_data = true,
        });
    }

    ~MintRollbackDurabilitySetup()
    {
        pnevmtxmintdb = std::move(previous_mint_db);
    }

    ObservedRollbackMintDB& MintDB()
    {
        return static_cast<ObservedRollbackMintDB&>(*pnevmtxmintdb);
    }

    void StoreTip(bool with_mint)
    {
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        std::vector<CMutableTransaction> transactions;
        if (with_mint) {
            CMintSyscoin mint;
            mint.nTxHash = mint_hash;
            mint.voutAssets.emplace_back(1, std::vector<CAssetOutValue>{{0, 1}});
            mint.vchTxParentNodes = {0x80};
            mint.vchReceiptParentNodes = {0x80};
            std::vector<unsigned char> payload;
            mint.SerializeData(payload);
            CMutableTransaction tx;
            tx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_MINT;
            tx.vin.emplace_back(COutPoint{m_coinbase_txns.front()->GetHash(), 0});
            tx.vout.emplace_back(1, CScript{} << OP_TRUE);
            tx.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
            tx.LoadAssets();
            BOOST_REQUIRE(!CMintSyscoin(CTransaction{tx}).IsNull());
            transactions.push_back(std::move(tx));
        }
        const CBlock block{CreateBlock(transactions, CScript{} << OP_TRUE,
                                      chainstate)};
        LOCK(::cs_main);
        parent_hash = chainman.ActiveTip()->GetBlockHash();
        stored_tip_hash = block.GetHash();
        const FlatFilePos pos{chainman.m_blockman.SaveBlockToDisk(
            block, chainman.ActiveHeight() + 1, nullptr)};
        BOOST_REQUIRE(!pos.IsNull());
        auto* index{chainman.m_blockman.AddToBlockIndex(
            block, chainman.m_best_header)};
        BOOST_REQUIRE(index != nullptr);
        chainman.ReceivedBlockTransactions(block, index, pos);
        CBlockUndo undo;
        auto& coins{chainstate.CoinsTip()};
        if (with_mint) {
            Coin input;
            BOOST_REQUIRE(coins.SpendCoin(block.vtx[1]->vin[0].prevout, &input));
            undo.vtxundo.emplace_back();
            undo.vtxundo.back().vprevout.push_back(std::move(input));
            mint_coin = COutPoint{block.vtx[1]->GetHash(), 0};
        }
        for (const auto& tx : block.vtx) AddCoins(coins, *tx, index->nHeight);
        BlockValidationState state;
        BOOST_REQUIRE(chainman.m_blockman.WriteUndoDataForBlock(undo, state, *index));
        index->RaiseValidity(BLOCK_VALID_SCRIPTS);
        coins.SetBestBlock(stored_tip_hash);
        chainstate.m_chain.SetTip(*index);
        if (with_mint) {
            MintDB().FlushDataToCache({mint_hash});
            BOOST_REQUIRE(MintDB().FlushCacheToDisk());
        }
        BOOST_REQUIRE(chainstate.CoinsDB().FlushWithSync(coins));
    }

    void ReopenCoins(bool prepare_replay, std::optional<uint256> new_head = std::nullopt)
    {
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        LOCK(::cs_main);
        const auto path{chainstate.CoinsDB().StoragePath()};
        BOOST_REQUIRE(path.has_value());
        chainstate.ResetCoinsViews();
        if (prepare_replay) {
            CDBWrapper db{DBParams{
                .path = *path,
                .cache_bytes = 1U << 20,
                .obfuscate = true,
            }};
            CDBBatch batch{db};
            batch.Erase(uint8_t{'B'});
            batch.Write(uint8_t{'H'},
                        std::vector<uint256>{new_head.value_or(parent_hash), stored_tip_hash});
            BOOST_REQUIRE(db.WriteBatch(batch, /*fSync=*/true));
        }
        chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                               /*should_wipe=*/false);
        chainstate.InitCoinsCache(1U << 23);
    }

    void CheckRollback(bool replay, bool fail_coins_sync, bool with_mint = true,
                       bool fail_coins_write = false)
    {
        StoreTip(with_mint);
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        if (replay) ReopenCoins(/*prepare_replay=*/true);
        LOCK(::cs_main);
        std::size_t coins_writes{0};
        std::size_t coins_syncs{0};
        std::size_t mint_writes{0};
        const bool fail{fail_coins_sync || fail_coins_write};
        chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool sync) {
            ++coins_writes;
            BOOST_CHECK(!sync);
            if (with_mint) {
                // The marker must remain visible until every coins batch
                // succeeds, including while a failing batch is attempted.
                BOOST_CHECK(MintDB().ExistsTx(mint_hash));
                BOOST_CHECK(MintDB().Exists(mint_hash));
            }
            return !fail_coins_write;
        });
        chainstate.CoinsDB().SetSyncCallbackForTesting(
            [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
                ++coins_syncs;
                BOOST_CHECK(with_mint);
                BOOST_CHECK_GT(coins_writes, 0U);
                BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent_hash);
                BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(mint_coin));
                BOOST_CHECK(MintDB().ExistsTx(mint_hash));
                BOOST_CHECK(MintDB().Exists(mint_hash));
                return !fail_coins_sync;
            });
        MintDB().before_write = [&](bool sync) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            ++mint_writes;
            BOOST_CHECK(sync);
            BOOST_CHECK_EQUAL(coins_syncs, 1U);
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent_hash);
            BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(mint_coin));
        };
        bool result;
        BlockValidationState state;
        if (replay) {
            result = chainstate.ReplayBlocks();
        } else {
            LOCK(chainstate.MempoolMutex());
            m_node.notifications->m_shutdown_on_fatal_error = false;
            result = chainstate.DisconnectTip(state, nullptr, /*bReverify=*/false);
            m_node.notifications->m_shutdown_on_fatal_error = true;
            m_node.exit_status.store(EXIT_SUCCESS);
            BOOST_CHECK_EQUAL(state.IsError(), fail);
        }
        chainstate.CoinsDB().SetWriteBatchCallbackForTesting({});
        chainstate.CoinsDB().SetSyncCallbackForTesting({});
        MintDB().before_write = {};
        BOOST_CHECK_EQUAL(result, !fail);
        if (with_mint || replay) BOOST_CHECK_GT(coins_writes, 0U);
        BOOST_CHECK_EQUAL(coins_syncs, with_mint && !fail_coins_write ? 1U : 0U);
        BOOST_CHECK_EQUAL(mint_writes, with_mint && !fail ? 1U : 0U);
        if (with_mint) {
            BOOST_CHECK_EQUAL(MintDB().ExistsTx(mint_hash), fail);
            // A failed coins write or sync must not queue an erase that a later
            // shutdown/cache flush could commit ahead of durable coin removal.
            BOOST_REQUIRE(MintDB().FlushCacheToDisk());
            BOOST_CHECK_EQUAL(MintDB().Exists(mint_hash), fail);
        }
        // A normal close/reopen preserves successful asynchronous writes even
        // when the sync was rejected. Power-loss recovery is covered in DB tests.
        ReopenCoins(/*prepare_replay=*/false);
        BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(mint_coin),
                          with_mint && fail_coins_write);
        if (!fail_coins_write && (with_mint || replay)) {
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent_hash);
            BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        }
    }
};
// SYSCOIN END: Mint rollback persistence ordering fixture.

// SYSCOIN BEGIN: Crash-safe NEVM root revocation across the coins transition.
struct ObservedDisconnectRootsDB final : CNEVMTxRootsDB {
    using CNEVMTxRootsDB::CNEVMTxRootsDB;
    std::function<void(bool)> observe_sync;
    std::function<bool()> before_write;
    std::function<void()> after_write;

protected:
    bool WriteCacheBatch(CDBBatch& batch, bool sync) override
    {
        if (observe_sync) observe_sync(sync);
        if (before_write && !before_write()) return false;
        const bool written{CDBWrapper::WriteBatch(batch, sync)};
        if (written && after_write) after_write();
        return written;
    }
};

struct NEVMRootRollbackSetup : StartupNEVMRecoverySetup {
    std::unique_ptr<CNEVMTxRootsDB> previous_roots_db{std::move(pnevmtxrootsdb)};
    std::unique_ptr<CNEVMMintedTxDB> previous_mint_db{std::move(pnevmtxmintdb)};
    const fs::path roots_path{m_path_root / "root-disconnect-roots"};
    const fs::path mints_path{m_path_root / "root-disconnect-mints"};
    const uint256 mint_hash{uint256S("b001")};
    const uint256 unclaimed_hash{uint256S("b002")};
    std::shared_ptr<const CBlock> checkpoint;
    std::shared_ptr<const CBlock> parent;
    CBlock carrier;
    CNEVMHeader canonical_header;
    CNEVMHeader orphan_header;
    COutPoint minted_coin;

    NEVMRootRollbackSetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/false}
    {
        pnevmtxrootsdb = std::make_unique<ObservedDisconnectRootsDB>(DBParams{
            .path = roots_path, .cache_bytes = 1U << 20, .wipe_data = true});
        pnevmtxmintdb = std::make_unique<ObservedRollbackMintDB>(DBParams{
            .path = mints_path, .cache_bytes = 1U << 20, .wipe_data = true});
    }

    ~NEVMRootRollbackSetup()
    {
        pnevmtxrootsdb = std::move(previous_roots_db);
        pnevmtxmintdb = std::move(previous_mint_db);
    }

    ObservedDisconnectRootsDB& RootsDB()
    {
        return static_cast<ObservedDisconnectRootsDB&>(*pnevmtxrootsdb);
    }

    ObservedRollbackMintDB& MintDB()
    {
        return static_cast<ObservedRollbackMintDB&>(*pnevmtxmintdb);
    }

    CBlockIndex* StoreBlockIndex(const CBlock& block)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        auto& chainman{*m_node.chainman};
        if (auto* index{chainman.m_blockman.LookupBlockIndex(block.GetHash())}) {
            return index;
        }
        auto* previous{chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock)};
        BOOST_REQUIRE(previous != nullptr);
        const FlatFilePos pos{chainman.m_blockman.SaveBlockToDisk(
            block, previous->nHeight + 1, nullptr)};
        BOOST_REQUIRE(!pos.IsNull());
        auto* index{chainman.m_blockman.AddToBlockIndex(block, chainman.m_best_header)};
        BOOST_REQUIRE(index != nullptr);
        chainman.ReceivedBlockTransactions(block, index, pos);
        index->RaiseValidity(BLOCK_VALID_SCRIPTS);
        return index;
    }

    void PrepareRootDisconnect(bool with_mint = true, bool lagging_coins = false,
                               bool alias_checkpoint = false)
    {
        if (lagging_coins) {
            // Q has both durable coins and usable NEVM roots. Its successors
            // P and A below remain ahead of the independently durable coins.
            checkpoint = MineNEVMBlock();
            SyncWithValidationInterfaceQueue();
            LOCK(::cs_main);
            auto& chainstate{m_node.chainman->ActiveChainstate()};
            BOOST_REQUIRE(RootsDB().FlushCacheToDisk());
            BOOST_REQUIRE(chainstate.CoinsDB().FlushWithSync(chainstate.CoinsTip()));
            if (alias_checkpoint) {
                CNEVMHeader header;
                BlockValidationState state;
                BOOST_REQUIRE(GetNEVMData(state, *checkpoint, header));
                nevm->template_block_hash = header.nBlockHash;
            }
        }
        parent = MineNEVMBlock();
        nevm->template_block_hash.reset();
        SyncWithValidationInterfaceQueue();
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        auto block_template{node::BlockAssembler{chainstate, nullptr}
                                .CreateNewBlock(CScript{} << OP_TRUE)};
        carrier = block_template->block;
        if (with_mint) {
            // A parsed, previously validated mint bookkeeping fixture. Its
            // independent unclaimed hash below has no consumed-proof marker.
            CMintSyscoin mint;
            mint.nTxHash = mint_hash;
            mint.voutAssets.emplace_back(1, std::vector<CAssetOutValue>{{0, 1}});
            mint.vchTxParentNodes = {0x80};
            mint.vchReceiptParentNodes = {0x80};
            std::vector<unsigned char> payload;
            mint.SerializeData(payload);
            CMutableTransaction tx;
            tx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_MINT;
            tx.vin.emplace_back(COutPoint{m_coinbase_txns.front()->GetHash(), 0});
            tx.vout.emplace_back(1, CScript{} << OP_TRUE);
            tx.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
            tx.LoadAssets();
            BOOST_REQUIRE(!CMintSyscoin(CTransaction{tx}).IsNull());
            carrier.vtx.push_back(MakeTransactionRef(std::move(tx)));
        }
        node::RegenerateCommitments(carrier, chainman,
                                    block_template->vchCoinbaseCommitmentExtra);
        carrier.fChecked = false;
        carrier.nNonce = 0;
        while (!CheckProofOfWork(carrier.GetHash(), carrier.nBits,
                                  chainman.GetConsensus())) ++carrier.nNonce;
        BlockValidationState header_state;
        BOOST_REQUIRE(GetNEVMData(header_state, carrier, orphan_header));
        BOOST_REQUIRE(GetNEVMData(header_state, *parent, canonical_header));
        BOOST_REQUIRE(orphan_header.nBlockHash != canonical_header.nBlockHash);
        LOCK(::cs_main);
        auto* index{StoreBlockIndex(carrier)};
        CBlockUndo undo;
        auto& coins{chainstate.CoinsTip()};
        if (with_mint) {
            Coin input;
            BOOST_REQUIRE(coins.SpendCoin(carrier.vtx[1]->vin[0].prevout, &input));
            undo.vtxundo.emplace_back();
            undo.vtxundo.back().vprevout.push_back(std::move(input));
            minted_coin = COutPoint{carrier.vtx[1]->GetHash(), 0};
            MintDB().FlushDataToCache({mint_hash});
            BOOST_REQUIRE(MintDB().FlushCacheToDisk());
        }
        for (const auto& tx : carrier.vtx) AddCoins(coins, *tx, index->nHeight);
        BlockValidationState undo_state;
        BOOST_REQUIRE(chainman.m_blockman.WriteUndoDataForBlock(undo, undo_state, *index));
        coins.SetBestBlock(carrier.GetHash());
        chainstate.m_chain.SetTip(*index);
        RootsDB().FlushDataToCache({
            {orphan_header.nBlockHash, {orphan_header.nTxRoot, orphan_header.nReceiptRoot}},
            {canonical_header.nBlockHash, {canonical_header.nTxRoot, canonical_header.nReceiptRoot}},
        });
        if (lagging_coins) {
            NEVMTxRoot root;
            if (alias_checkpoint) {
                BOOST_REQUIRE(RootsDB().Read(canonical_header.nBlockHash, root));
                BOOST_REQUIRE(root.nTxRoot != canonical_header.nTxRoot);
            } else {
                BOOST_REQUIRE(!RootsDB().Read(canonical_header.nBlockHash, root));
            }
            BOOST_REQUIRE(!RootsDB().Read(orphan_header.nBlockHash, root));
            BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == checkpoint->GetHash());
        } else {
            BOOST_REQUIRE(RootsDB().FlushCacheToDisk());
            BOOST_REQUIRE(chainstate.CoinsDB().FlushWithSync(coins));
        }
        nevm->applied_count = lagging_coins ? 3 : 2;
        nevm->applied_hash = carrier.GetHash();
        nevm->disconnected_blocks.clear();
    }

    void SaveRootCrashManifest(const fs::path& crash_path,
                               const CBlock* replacement = nullptr)
    {
        LOCK(::cs_main);
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        CDBWrapper manifest{DBParams{
            .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
        CDBBatch batch{manifest};
        batch.Write(std::string{"fixture_root"}, fs::PathToString(m_path_root));
        batch.Write(std::string{"coins_path"},
                    fs::PathToString(*chainstate.CoinsDB().StoragePath()));
        const auto write_block = [&](const std::string& key, const CBlock& block) {
            CDataStream bytes{SER_DISK, CLIENT_VERSION};
            bytes << block;
            batch.Write(key, std::vector<uint8_t>{
                UCharCast(bytes.data()), UCharCast(bytes.data() + bytes.size())});
        };
        if (checkpoint) write_block("checkpoint", *checkpoint);
        write_block("parent", *parent);
        write_block("carrier", carrier);
        if (replacement) write_block("replacement", *replacement);
        BOOST_REQUIRE(manifest.WriteBatch(batch, /*fSync=*/true));
    }

    struct RootCrashState {
        fs::path fixture_root;
        fs::path coins_path;
        CBlock checkpoint;
        CBlock parent;
        CBlock carrier;
        std::optional<CBlock> replacement;
    };

    RootCrashState ReadRootCrashManifest(const fs::path& crash_path)
    {
        CDBWrapper manifest{DBParams{
            .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
        RootCrashState saved;
        std::string fixture_root_string, coins_path_string;
        BOOST_REQUIRE(manifest.Read(std::string{"fixture_root"}, fixture_root_string));
        BOOST_REQUIRE(manifest.Read(std::string{"coins_path"}, coins_path_string));
        saved.fixture_root = fs::u8path(fixture_root_string);
        saved.coins_path = fs::u8path(coins_path_string);
        BOOST_REQUIRE(saved.fixture_root != m_path_root);
        BOOST_REQUIRE(saved.fixture_root.parent_path() == m_path_root.parent_path());
        const auto read_block = [&](const std::string& key, CBlock& block) {
            std::vector<uint8_t> bytes;
            BOOST_REQUIRE(manifest.Read(key, bytes));
            CDataStream stream{bytes, SER_DISK, CLIENT_VERSION};
            stream >> block;
            BOOST_REQUIRE(stream.empty());
        };
        read_block("checkpoint", saved.checkpoint);
        read_block("parent", saved.parent);
        read_block("carrier", saved.carrier);
        if (manifest.Exists(std::string{"replacement"})) {
            saved.replacement.emplace();
            read_block("replacement", *saved.replacement);
        }
        return saved;
    }

    void TrackRootRecoveryDirectory(const fs::path& crash_path)
    {
        CDBWrapper manifest{DBParams{
            .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
        std::vector<std::string> recovery_roots;
        manifest.Read(std::string{"recovery_roots"}, recovery_roots);
        recovery_roots.push_back(fs::PathToString(m_path_root));
        BOOST_REQUIRE(manifest.Write(std::string{"recovery_roots"},
                                      recovery_roots, /*fSync=*/true));
    }

    void OpenRootCrashState(const RootCrashState& saved)
    {
        pnevmtxrootsdb = std::make_unique<ObservedDisconnectRootsDB>(DBParams{
            .path = saved.fixture_root / "root-disconnect-roots", .cache_bytes = 1U << 20});
        pnevmtxmintdb = std::make_unique<ObservedRollbackMintDB>(DBParams{
            .path = saved.fixture_root / "root-disconnect-mints", .cache_bytes = 1U << 20});
        LOCK(::cs_main);
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        chainstate.ResetCoinsViews();
        chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                               /*should_wipe=*/false, saved.coins_path);
        StoreBlockIndex(saved.checkpoint);
        auto* parent_index{StoreBlockIndex(saved.parent)};
        auto* carrier_index{StoreBlockIndex(saved.carrier)};
        if (saved.replacement) {
            StoreBlockIndex(*saved.replacement);
            // The aligned-publication replay fixture uses coinbase-only
            // discarded blocks, so their authentic undo records are empty.
            BOOST_REQUIRE_EQUAL(saved.parent.vtx.size(), 1U);
            BOOST_REQUIRE_EQUAL(saved.carrier.vtx.size(), 1U);
            BlockValidationState state;
            for (auto* index : {parent_index, carrier_index}) {
                BOOST_REQUIRE(m_node.chainman->m_blockman.WriteUndoDataForBlock(
                    CBlockUndo{}, state, *index));
            }
        }
    }

    void RunRootCrashChild(const fs::path& crash_path, const std::string& cut)
    {
#if defined(HAVE_BOOST_PROCESS) || defined(ENABLE_EXTERNAL_SIGNER)
#if BOOST_VERSION >= 108800
        namespace bp = boost::process::v1;
#else
        namespace bp = boost::process;
#endif
        const std::vector<std::string> args{
            "--run_test=validation_chainstatemanager_tests/nevm_disconnect_root_crash_child",
            "--", "NEVM_ROOT_CRASH_CHILD", fs::PathToString(crash_path), cut};
        bp::child child{bp::exe = boost::unit_test::framework::master_test_suite().argv[0],
                         bp::args = args};
        const auto deadline{std::chrono::steady_clock::now() + std::chrono::minutes{2}};
        while (child.running() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
        const bool timed_out{child.running()};
        if (timed_out) child.terminate();
        child.wait();
        BOOST_REQUIRE_MESSAGE(!timed_out, "Owned crash-test child timed out");
        BOOST_REQUIRE_EQUAL(child.exit_code(), 73);
#endif
    }

    bool DisconnectRootTip(BlockValidationState& state, bool reverify)
    {
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        LOCK2(::cs_main, chainstate.MempoolMutex());
        m_node.notifications->m_shutdown_on_fatal_error = false;
        const bool disconnected{chainstate.DisconnectTip(state, nullptr, reverify)};
        m_node.notifications->m_shutdown_on_fatal_error = true;
        m_node.exit_status.store(EXIT_SUCCESS);
        return disconnected;
    }
};
// SYSCOIN END: Crash-safe NEVM root revocation across the coins transition.

struct FreshNEVMStartupSetup : ChainTestingSetup {
    const bool previous_nevm_connection{fNEVMConnection};
    const bool previous_regtest{fRegTest};
    std::shared_ptr<StartupNEVMSubscriber> nevm{
        std::make_shared<StartupNEVMSubscriber>()};

    FreshNEVMStartupSetup()
        : ChainTestingSetup{ChainType::REGTEST,
                            {"-nevmstartheight=101"}}
    {
        RegisterSharedValidationInterface(nevm);
        fNEVMConnection = true;
        fRegTest = true;
    }

    ~FreshNEVMStartupSetup()
    {
        UnregisterValidationInterface(nevm.get());
        SyncWithValidationInterfaceQueue();
        fNEVMConnection = previous_nevm_connection;
        fRegTest = previous_regtest;
    }
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

BOOST_FIXTURE_TEST_CASE(nevm_connect_operational_errors_preserve_block_candidate,
                        StartupNEVMRecoverySetup)
{
    for (const auto* error : {"nevm-not-connected", "ZMQ_RCVTIMEO",
                             "nevm-connect-not-sent", "nevm-response-invalid-parts",
                             "nevm-response-wrong-command", "nevm-response-not-found"}) {
        BOOST_TEST_CONTEXT(error) { CheckConnectError(error); }
    }
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_engine_rejection_invalidates_block_candidate,
                        StartupNEVMRecoverySetup)
{
    CheckConnectError("nevm-connect-response-invalid-data", /*engine_rejection=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_managed_shutdown_preserves_block_candidate,
                        ManagedNEVMShutdownSetup)
{
    BOOST_REQUIRE(m_node.chainman->GethCommandLine() ==
                  std::vector<std::string>{"--exitwhensynced"});
    for (const auto* error : {"nevm-connect-response-invalid-data", "nevm-response-not-found"}) {
        BOOST_TEST_CONTEXT(error) {
            CheckConnectError(error, /*engine_rejection=*/false, /*managed_exit=*/true);
        }
    }
}

// SYSCOIN BEGIN: Valid mint candidates survive local NEVM database read errors.
BOOST_FIXTURE_TEST_CASE(nevm_mint_root_read_error_preserves_block_candidate,
                        NEVMMintReadErrorSetup)
{
    CheckReadError(/*roots_error=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_mint_marker_read_error_preserves_block_candidate,
                        NEVMMintReadErrorSetup)
{
    CheckReadError(/*roots_error=*/false);
}
// SYSCOIN END: Valid mint candidates survive local NEVM database read errors.

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
    recognized_pq_history_revocation_reenters_pending,
    TestChain100Setup)
{
    using Access = llmq::test::PQHistoryReauthenticationTestAccess;
    static_assert(!std::is_default_constructible_v<PQHistoryReauthentication>);
    static_assert(!std::is_constructible_v<PQHistoryReauthentication,
        const ChainstateManager&, const CBlockIndex&, const CBlockIndex&,
        const CBlockIndex*, const CBlockIndex*, const uint256&, uint64_t>);
    auto& chainman{static_cast<TestChainstateManager&>(
        *Assert(m_node.chainman))};
    chainman.ResetIbd(PQHistoryAuthState::READY);
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        CBlockIndex* original_tip{chainman.ActiveTip()};
        BOOST_REQUIRE(original_tip && original_tip->nHeight >= 100);
        struct RestoreTip {
            CChain& chain;
            CBlockIndex* tip;
            ~RestoreTip() { chain.SetTip(*tip); }
        } restore{chainman.ActiveChain(), original_tip};
        const CBlockIndex* coverage{original_tip->GetAncestor(90)};
        const CBlockIndex* earlier_floor{original_tip->GetAncestor(70)};
        const CBlockIndex* floor{original_tip->GetAncestor(80)};
        BOOST_REQUIRE(coverage && earlier_floor && floor);
        const uint256 dependency{RecoveryFixtureHash(910'001)};
        const auto make = [&](const CBlockIndex& selected,
                              const CBlockIndex* previous,
                              const CBlockIndex* current)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            return Access::Make(chainman, *coverage, selected, previous,
                current, dependency,
                chainman.GetPQProvenanceRevocationRevision());
        };
        const auto check_reentry = [&](const PQHistoryReauthentication& proof)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            BOOST_REQUIRE(chainman.TryReenterPendingPQHistoryAuthentication(proof));
            BOOST_CHECK(chainman.GetPQHistoryAuthState() == PQHistoryAuthState::PENDING);
            BOOST_CHECK(chainman.HasCompletedInitialBlockDownload());
            BOOST_CHECK(!chainman.IsInitialBlockDownload());
            BOOST_CHECK(chainman.TryReenterPendingPQHistoryAuthentication(proof));
            BOOST_CHECK(chainman.PublishPQHistoryAuthState(PQHistoryAuthState::PENDING));
            BOOST_CHECK(chainman.PublishPQHistoryAuthState(PQHistoryAuthState::READY));
            BOOST_CHECK(!chainman.PublishPQHistoryAuthState(PQHistoryAuthState::PENDING));
        };
        const auto unchanged{make(*original_tip, floor, floor)};
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(unchanged));

        // A selected tip below E revokes coverage even while best_header still
        // points to the old branch. Authentication follows ActiveTip, not headers.
        CBlockIndex* replacement_tip{original_tip->GetAncestor(89)};
        BOOST_REQUIRE(replacement_tip);
        chainman.ActiveChain().SetTip(*replacement_tip);
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(unchanged));
        const auto revoked{make(*replacement_tip, floor, floor)};
        auto wrong_owner{revoked};
        Access::RemoveOwner(wrong_owner);
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(wrong_owner));
        auto unknown_coverage{revoked};
        Access::ReplaceCoverageHash(unknown_coverage, RecoveryFixtureHash(910'002));
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(unknown_coverage));
        const auto no_dependency{Access::Make(chainman, *coverage,
            *replacement_tip, floor, floor, {},
            chainman.GetPQProvenanceRevocationRevision())};
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(no_dependency));
        const auto future_revision{Access::Make(chainman, *coverage,
            *replacement_tip, floor, floor, dependency,
            chainman.GetPQProvenanceRevocationRevision() + 1)};
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(future_revision));
        check_reentry(revoked);
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*replacement_tip, floor, earlier_floor)));
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*replacement_tip, floor, nullptr)));
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*replacement_tip, floor, coverage)));
        CBlockIndex* below_floor{original_tip->GetAncestor(79)};
        BOOST_REQUIRE(below_floor);
        chainman.ActiveChain().SetTip(*below_floor);
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*below_floor, floor, floor)));
        chainman.ActiveChain().SetTip(*replacement_tip);
        check_reentry(make(*replacement_tip, nullptr, nullptr));

        chainman.ActiveChain().SetTip(*original_tip);
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*original_tip, floor, floor)));
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*original_tip, floor, earlier_floor)));
        check_reentry(make(*original_tip, earlier_floor, floor));
        check_reentry(make(*original_tip, nullptr, floor));
        BOOST_CHECK(!chainman.TryReenterPendingPQHistoryAuthentication(
            make(*original_tip, floor, coverage)));
        const auto provenance_revoked{make(*original_tip, floor, floor)};
        Access::RevokeProvenance(chainman);
        check_reentry(provenance_revoked);
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

// SYSCOIN BEGIN: Coins removal must be synchronous before mint-marker erasure.
BOOST_FIXTURE_TEST_CASE(mint_disconnect_syncs_coins_before_marker_erase,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/false, /*fail_coins_sync=*/false);
}

BOOST_FIXTURE_TEST_CASE(mint_disconnect_failed_coins_sync_preserves_marker,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/false, /*fail_coins_sync=*/true);
}

BOOST_FIXTURE_TEST_CASE(mint_disconnect_failed_coins_write_preserves_marker,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/false, /*fail_coins_sync=*/false,
                  /*with_mint=*/true, /*fail_coins_write=*/true);
}

BOOST_FIXTURE_TEST_CASE(mint_replay_syncs_coins_before_marker_erase,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/true, /*fail_coins_sync=*/false);
}

BOOST_FIXTURE_TEST_CASE(mint_replay_failed_coins_sync_preserves_marker,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/true, /*fail_coins_sync=*/true);
}

BOOST_FIXTURE_TEST_CASE(mint_replay_failed_coins_write_preserves_marker,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/true, /*fail_coins_sync=*/false,
                  /*with_mint=*/true, /*fail_coins_write=*/true);
}

BOOST_FIXTURE_TEST_CASE(nonmint_disconnect_preserves_async_coins_flush,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/false, /*fail_coins_sync=*/false,
                  /*with_mint=*/false);
}

BOOST_FIXTURE_TEST_CASE(nonmint_replay_preserves_async_coins_flush,
                        MintRollbackDurabilitySetup)
{
    CheckRollback(/*replay=*/true, /*fail_coins_sync=*/false,
                  /*with_mint=*/false);
}

BOOST_FIXTURE_TEST_CASE(mint_replay_retains_proof_reconnected_on_new_branch,
                        MintRollbackDurabilitySetup)
{
    StoreTip(/*with_mint=*/true);
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    LOCK(::cs_main);
    auto* old_index{chainman.m_blockman.LookupBlockIndex(stored_tip_hash)};
    BOOST_REQUIRE(old_index != nullptr);
    CBlock replacement;
    BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(replacement, *old_index));
    CMutableTransaction replacement_mint{*replacement.vtx[1]};
    replacement_mint.nLockTime = 1;
    replacement.vtx[1] = MakeTransactionRef(std::move(replacement_mint));
    ++replacement.nTime;
    node::RegenerateCommitments(replacement, chainman, {});
    replacement.nNonce = 0;
    while (!CheckProofOfWork(replacement.GetHash(), replacement.nBits,
                              chainman.GetConsensus())) ++replacement.nNonce;
    const COutPoint replacement_coin{replacement.vtx[1]->GetHash(), 0};
    BOOST_REQUIRE(replacement_coin != mint_coin);
    BOOST_REQUIRE(CMintSyscoin(*replacement.vtx[1]).nTxHash == mint_hash);
    const auto pos{chainman.m_blockman.SaveBlockToDisk(replacement, old_index->nHeight, nullptr)};
    BOOST_REQUIRE(!pos.IsNull());
    auto* replacement_index{chainman.m_blockman.AddToBlockIndex(replacement, chainman.m_best_header)};
    BOOST_REQUIRE(replacement_index != nullptr);
    chainman.ReceivedBlockTransactions(replacement, replacement_index, pos);
    replacement_index->RaiseValidity(BLOCK_VALID_SCRIPTS);
    ReopenCoins(/*prepare_replay=*/true, replacement.GetHash());
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == replacement.GetHash());
    BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(mint_coin));
    BOOST_CHECK(chainstate.CoinsDB().HaveCoin(replacement_coin));
    BOOST_CHECK(MintDB().ExistsTx(mint_hash));
    BOOST_REQUIRE(MintDB().FlushCacheToDisk());
    BOOST_CHECK(MintDB().Exists(mint_hash));
}
// SYSCOIN END: Coins removal must be synchronous before mint-marker erasure.

// SYSCOIN BEGIN: Exercise real process loss and empty-HEADS startup recovery.
BOOST_FIXTURE_TEST_CASE(nevm_disconnect_root_crash_child, NEVMRootRollbackSetup,
                        *boost::unit_test::disabled())
{
    const auto args{G_TEST_COMMAND_LINE_ARGUMENTS()};
    if (args.empty() || std::string{args[0]} != "NEVM_ROOT_CRASH_CHILD") {
        BOOST_TEST_MESSAGE("Crash helper requires an owned parent-test invocation");
        return;
    }
    BOOST_REQUIRE_EQUAL(args.size(), 3U);
    BOOST_REQUIRE_EQUAL(std::string{args[0]}, "NEVM_ROOT_CRASH_CHILD");
    const fs::path crash_path{fs::u8path(args[1])};
    const std::string cut{args[2]};
    BOOST_REQUIRE(crash_path.is_absolute());
    BOOST_REQUIRE(fs::is_directory(crash_path));
    if (cut == "during-aligned-publication-alias-replay") {
        const auto saved{ReadRootCrashManifest(crash_path)};
        BOOST_REQUIRE(saved.replacement);
        TrackRootRecoveryDirectory(crash_path);
        OpenRootCrashState(saved);
        LOCK(::cs_main);
        auto& coins_db{m_node.chainman->ActiveChainstate().CoinsDB()};
        BOOST_REQUIRE(RootsDB().GetPublishedTip() == saved.replacement->GetHash());
        BOOST_REQUIRE(!RootsDB().GetPendingDisconnect());
        BOOST_REQUIRE(coins_db.GetHeadBlocks() == (std::vector<uint256>{
            saved.replacement->GetHash(), saved.carrier.GetHash()}));
        CNEVMHeader canonical;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, *saved.replacement, canonical));
        const auto check_alias = [&] {
            NEVMTxRoot root;
            BOOST_REQUIRE(RootsDB().Read(canonical.nBlockHash, root));
            BOOST_CHECK(root.nTxRoot == canonical.nTxRoot);
            BOOST_CHECK(root.nReceiptRoot == canonical.nReceiptRoot);
        };
        std::size_t coins_syncs{0};
        coins_db.SetSyncCallbackForTesting([&] {
            ++coins_syncs;
            check_alias();
            return true;
        });
        RootsDB().before_write = [&] {
            BOOST_REQUIRE_EQUAL(coins_syncs, 1U);
            check_alias();
            return true;
        };
        RootsDB().after_write = [&] {
            // T already equals the now-durable coins endpoint. If this
            // cleanup erased a canonical alias, the cold fast path below
            // would have no remaining metadata with which to repair it.
            check_alias();
            uint256 published;
            BOOST_REQUIRE(RootsDB().Read(uint8_t{'T'}, published));
            BOOST_REQUIRE(published == saved.replacement->GetHash());
            BOOST_REQUIRE(!RootsDB().Exists(uint8_t{'D'}));
            BOOST_REQUIRE(coins_db.GetBestBlock() == saved.replacement->GetHash());
            BOOST_REQUIRE(coins_db.GetHeadBlocks().empty());
            std::_Exit(73);
        };
        m_node.chainman->ActiveChainstate().ReplayBlocks();
        BOOST_FAIL("ReplayBlocks did not reach the aligned-publication cleanup crash");
        return;
    }
    if (cut == "during-lagging-cleanup") {
        const auto saved{ReadRootCrashManifest(crash_path)};
        TrackRootRecoveryDirectory(crash_path);
        OpenRootCrashState(saved);
        LOCK(::cs_main);
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == saved.checkpoint.GetHash());
        BOOST_REQUIRE(RootsDB().GetPendingDisconnect());
        std::size_t coins_syncs{0};
        chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
            ++coins_syncs;
            return true;
        });
        RootsDB().after_write = [&] {
            // The first cleanup batch may already remove surplus rows. Its
            // durable obligation must outlive both that write and this crash.
            BOOST_REQUIRE_EQUAL(coins_syncs, 1U);
            BOOST_REQUIRE(RootsDB().Exists(uint8_t{'D'}));
            std::_Exit(73);
        };
        chainstate.ReplayBlocks();
        BOOST_FAIL("ReplayBlocks did not reach the requested cleanup crash");
        return;
    }
    BOOST_REQUIRE(!fs::exists(crash_path / "manifest"));
    const bool alias_checkpoint{cut == "after-aliased-retained-roots-before-coins"};
    const bool forward_only{cut == "after-forward-roots-before-coins"};
    const bool aligned_replay{cut == "before-aligned-publication-alias-replay"};
    const bool lagging_coins{
        cut == "after-retained-roots-before-coins" || alias_checkpoint || forward_only || aligned_replay};
    PrepareRootDisconnect(/*with_mint=*/!aligned_replay, lagging_coins, alias_checkpoint);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    if (aligned_replay) {
        LOCK(::cs_main);
        CBlock replacement{*parent};
        ++replacement.nTime;
        replacement.nNonce = 0;
        replacement.fChecked = false;
        while (!CheckProofOfWork(replacement.GetHash(), replacement.nBits,
                                  m_node.chainman->GetConsensus())) ++replacement.nNonce;
        BOOST_REQUIRE(replacement.GetHash() != parent->GetHash());
        StoreBlockIndex(replacement);
        BOOST_REQUIRE(RootsDB().FlushCacheToDisk());
        // T=R describes an already-published canonical root set. Retain the
        // shared P/R key and Q; remove the key unique to abandoned carrier A.
        BOOST_REQUIRE(RootsDB().FlushErase({orphan_header.nBlockHash}));
        BOOST_REQUIRE(RootsDB().RecordPublishedTip(replacement.GetHash()));
        BOOST_REQUIRE(chainstate.CoinsDB().FlushWithSync(chainstate.CoinsTip()));
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == carrier.GetHash());
        const fs::path coins_path{*chainstate.CoinsDB().StoragePath()};
        SaveRootCrashManifest(crash_path, &replacement);
        chainstate.ResetCoinsViews();
        {
            CDBWrapper coins{DBParams{
                .path = coins_path, .cache_bytes = 1U << 20, .obfuscate = true}};
            CDBBatch batch{coins};
            batch.Erase(uint8_t{'B'});
            batch.Write(uint8_t{'H'}, std::vector<uint256>{
                replacement.GetHash(), carrier.GetHash()});
            BOOST_REQUIRE(coins.WriteBatch(batch, /*fSync=*/true));
        }
        std::_Exit(73);
    }
    SaveRootCrashManifest(crash_path);
    if (forward_only) {
        // Ordinary forward batching has no disconnect journal, but the root
        // publisher must still describe the suffix ahead of durable coins Q.
        BOOST_REQUIRE(RootsDB().RecordPublishedTip(carrier.GetHash()));
        BOOST_REQUIRE(RootsDB().FlushCacheToDisk());
        BOOST_REQUIRE(!RootsDB().GetPendingDisconnect());
        LOCK(::cs_main);
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == checkpoint->GetHash());
        std::_Exit(73);
    }
    std::size_t root_writes{0};
    std::size_t coins_syncs{0};
    RootsDB().before_write = [&] {
        ++root_writes;
        if (cut == "before-root-prepare" && root_writes == 1) std::_Exit(73);
        if (cut == "after-coins-sync" && coins_syncs == 1) {
            std::_Exit(73);
        }
        return true;
    };
    RootsDB().after_write = [&] {
        if (cut == "after-root-prepare" && root_writes == 1) std::_Exit(73);
    };
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
            ++coins_syncs;
            return true;
        });
        if (lagging_coins) {
            auto& coins_db{chainstate.CoinsDB()};
            coins_db.SetWriteBatchCallbackForTesting([&](bool) {
                NEVMTxRoot durable_parent;
                BOOST_REQUIRE(RootsDB().Read(canonical_header.nBlockHash, durable_parent));
                BOOST_REQUIRE(durable_parent.nTxRoot == canonical_header.nTxRoot);
                BOOST_REQUIRE(durable_parent.nReceiptRoot == canonical_header.nReceiptRoot);
                BOOST_REQUIRE(coins_db.GetBestBlock() == checkpoint->GetHash());
                BOOST_REQUIRE_EQUAL(coins_syncs, 0U);
                BOOST_REQUIRE(RootsDB().GetPendingDisconnect());
                std::_Exit(73);
                return false;
            });
        }
    }
    MintDB().before_write = [&](bool sync) {
        if (cut == "after-journal-clear") {
            BOOST_REQUIRE(sync);
            BOOST_REQUIRE_EQUAL(coins_syncs, 1U);
            std::_Exit(73);
        }
    };
    BlockValidationState state;
    DisconnectRootTip(state, /*reverify=*/true);
    BOOST_FAIL("DisconnectTip did not reach the requested crash cut: " + cut);
}

BOOST_FIXTURE_TEST_CASE(nevm_disconnect_roots_cold_recovery,
                        NEVMRootRollbackSetup)
{
#if defined(HAVE_BOOST_PROCESS) || defined(ENABLE_EXTERNAL_SIGNER)
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    for (const std::string cut : {"before-root-prepare", "after-root-prepare",
                                  "after-coins-sync", "after-journal-clear"}) {
        BOOST_TEST_CONTEXT("cold reopen at " << cut) {
            const fs::path crash_path{m_path_root / fs::u8path(cut)};
            BOOST_REQUIRE(fs::create_directories(crash_path));
            RunRootCrashChild(crash_path, cut);

            CDBWrapper manifest{DBParams{
                .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
            std::string fixture_root_string, coins_path_string;
            std::vector<uint8_t> parent_bytes, carrier_bytes;
            CBlock saved_parent, saved_carrier;
            BOOST_REQUIRE(manifest.Read(std::string{"fixture_root"}, fixture_root_string));
            BOOST_REQUIRE(manifest.Read(std::string{"coins_path"}, coins_path_string));
            BOOST_REQUIRE(manifest.Read(std::string{"parent"}, parent_bytes));
            BOOST_REQUIRE(manifest.Read(std::string{"carrier"}, carrier_bytes));
            CDataStream parent_stream{parent_bytes, SER_DISK, CLIENT_VERSION};
            CDataStream carrier_stream{carrier_bytes, SER_DISK, CLIENT_VERSION};
            parent_stream >> saved_parent;
            carrier_stream >> saved_carrier;
            BOOST_REQUIRE(parent_stream.empty());
            BOOST_REQUIRE(carrier_stream.empty());
            const fs::path child_root{fs::u8path(fixture_root_string)};
            BOOST_REQUIRE(child_root != m_path_root);
            BOOST_REQUIRE(child_root.parent_path() == m_path_root.parent_path());
            CNEVMHeader orphan, canonical;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, saved_carrier, orphan));
            BOOST_REQUIRE(GetNEVMData(state, saved_parent, canonical));
            BOOST_REQUIRE_EQUAL(saved_carrier.vtx.size(), 2U);
            const COutPoint minted{saved_carrier.vtx[1]->GetHash(), 0};

            // These are new DB objects in a process that never held the
            // writer's caches; _Exit skipped every writer-side destructor.
            pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(DBParams{
                .path = child_root / "root-disconnect-roots", .cache_bytes = 1U << 20});
            pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(DBParams{
                .path = child_root / "root-disconnect-mints", .cache_bytes = 1U << 20});
            LOCK(::cs_main);
            chainstate.ResetCoinsViews();
            chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                                   /*should_wipe=*/false, fs::u8path(coins_path_string));
            const bool old_coins{cut == "before-root-prepare" || cut == "after-root-prepare"};
            const bool pending{cut == "after-root-prepare" || cut == "after-coins-sync"};
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() ==
                        (old_coins ? saved_carrier.GetHash() : saved_parent.GetHash()));
            BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
            BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(minted), old_coins);
            BOOST_CHECK(pnevmtxmintdb->ExistsTx(mint_hash));
            BOOST_CHECK(!pnevmtxmintdb->ExistsTx(unclaimed_hash));
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->GetPendingDisconnect().has_value(), pending);
            NEVMTxRoot roots;
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(orphan.nBlockHash, roots),
                              cut == "before-root-prepare");
            BOOST_REQUIRE(pnevmtxrootsdb->ReadTxRoots(canonical.nBlockHash, roots));
            BOOST_CHECK(roots.nTxRoot == canonical.nTxRoot);
            BOOST_CHECK(roots.nReceiptRoot == canonical.nReceiptRoot);

            // Recreate only the two stored indexes above the fixture's exact
            // shared 100-block base, then run the normal startup entry point.
            StoreBlockIndex(saved_parent);
            StoreBlockIndex(saved_carrier);
            if (pending) {
                chainstate.CoinsDB().SetSyncCallbackForTesting([] { return false; });
                BOOST_CHECK(!chainstate.ReplayBlocks());
                BOOST_CHECK(pnevmtxrootsdb->GetPendingDisconnect());
                BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(orphan.nBlockHash, roots));
            }
            std::size_t recovery_syncs{0};
            chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
                ++recovery_syncs;
                return true;
            });
            BOOST_REQUIRE(chainstate.ReplayBlocks());
            chainstate.CoinsDB().SetSyncCallbackForTesting({});
            BOOST_CHECK_EQUAL(recovery_syncs, pending ? 1U : 0U);
            BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(orphan.nBlockHash, roots), old_coins);
            if (old_coins) {
                BOOST_CHECK(roots.nTxRoot == orphan.nTxRoot);
                BOOST_CHECK(roots.nReceiptRoot == orphan.nReceiptRoot);
            }
            BOOST_CHECK(pnevmtxrootsdb->ReadTxRoots(canonical.nBlockHash, roots));
            BOOST_CHECK(pnevmtxmintdb->ExistsTx(mint_hash));
            BOOST_CHECK(!pnevmtxmintdb->ExistsTx(unclaimed_hash));
            BOOST_CHECK(nevm->connected_blocks.empty());
            BOOST_CHECK(nevm->disconnected_blocks.empty());
            chainstate.ResetCoinsViews();
            pnevmtxrootsdb.reset();
            pnevmtxmintdb.reset();
            fs::remove_all(child_root);
        }
    }
#else
    BOOST_TEST_MESSAGE("Skipping subprocess root-crash regression: Boost.Process unavailable");
#endif
}

BOOST_FIXTURE_TEST_CASE(nevm_disconnect_roots_recover_lagging_coins,
                        NEVMRootRollbackSetup)
{
#if defined(HAVE_BOOST_PROCESS) || defined(ENABLE_EXTERNAL_SIGNER)
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    for (const std::string mode : {"lagging-q", "forward-root-flush", "repeated-cleanup",
                                  "replacement-root-alias", "common-ancestor-root-alias"}) {
        BOOST_TEST_CONTEXT(mode) {
            const bool ancestor_alias{mode == "common-ancestor-root-alias"};
            const bool forward_only{mode == "forward-root-flush"};
            const fs::path crash_path{m_path_root / fs::u8path(mode)};
            BOOST_REQUIRE(fs::create_directories(crash_path));
            RunRootCrashChild(crash_path, forward_only
                ? "after-forward-roots-before-coins"
                : ancestor_alias ? "after-aliased-retained-roots-before-coins"
                                 : "after-retained-roots-before-coins");
            if (mode == "repeated-cleanup") {
                // Both recovery processes lose power after a cleanup write,
                // leaving a cold third recovery to finish the same obligation.
                RunRootCrashChild(crash_path, "during-lagging-cleanup");
                RunRootCrashChild(crash_path, "during-lagging-cleanup");
            }
            const auto saved{ReadRootCrashManifest(crash_path)};
            OpenRootCrashState(saved);
            CNEVMHeader checkpoint_header, parent_header, carrier_header;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, saved.checkpoint, checkpoint_header));
            BOOST_REQUIRE(GetNEVMData(state, saved.parent, parent_header));
            BOOST_REQUIRE(GetNEVMData(state, saved.carrier, carrier_header));
            BOOST_REQUIRE_EQUAL(saved.carrier.vtx.size(), 2U);
            const COutPoint minted{saved.carrier.vtx[1]->GetHash(), 0};
            LOCK(::cs_main);
            BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == saved.checkpoint.GetHash());
            BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
            BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(minted));
            BOOST_REQUIRE_EQUAL(RootsDB().GetPendingDisconnect().has_value(), !forward_only);
            BOOST_CHECK(MintDB().ExistsTx(mint_hash));
            BOOST_CHECK(!MintDB().ExistsTx(unclaimed_hash));
            NEVMTxRoot root;
            BOOST_CHECK_EQUAL(RootsDB().Read(parent_header.nBlockHash, root),
                              mode != "repeated-cleanup");
            BOOST_CHECK_EQUAL(RootsDB().ReadTxRoots(carrier_header.nBlockHash, root), forward_only);
            BOOST_REQUIRE(RootsDB().ReadTxRoots(checkpoint_header.nBlockHash, root));
            BOOST_CHECK(root.nTxRoot == (ancestor_alias
                ? parent_header.nTxRoot : checkpoint_header.nTxRoot));
            BOOST_CHECK(root.nReceiptRoot == (ancestor_alias
                ? parent_header.nReceiptRoot : checkpoint_header.nReceiptRoot));

            CBlockIndex* recovered{chainman.m_blockman.LookupBlockIndex(saved.checkpoint.GetHash())};
            if (mode == "replacement-root-alias") {
                // A different Syscoin carrier on the recovered branch can
                // legitimately commit the same NEVM root key as orphan P.
                CBlock replacement{saved.parent};
                ++replacement.nTime;
                replacement.nNonce = 0;
                replacement.fChecked = false;
                while (!CheckProofOfWork(replacement.GetHash(), replacement.nBits,
                                          chainman.GetConsensus())) ++replacement.nNonce;
                BOOST_REQUIRE(replacement.GetHash() != saved.parent.GetHash());
                CNEVMHeader replacement_header;
                BOOST_REQUIRE(GetNEVMData(state, replacement, replacement_header));
                BOOST_REQUIRE(replacement_header.nBlockHash == parent_header.nBlockHash);
                recovered = StoreBlockIndex(replacement);
                chainstate.ResetCoinsViews();
                {
                    CDBWrapper coins{DBParams{
                        .path = saved.coins_path, .cache_bytes = 1U << 20,
                        .obfuscate = true}};
                    CDBBatch batch{coins};
                    batch.Erase(uint8_t{'B'});
                    batch.Write(uint8_t{'H'}, std::vector<uint256>{
                        replacement.GetHash(), saved.checkpoint.GetHash()});
                    BOOST_REQUIRE(coins.WriteBatch(batch, /*fSync=*/true));
                }
                chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                                       /*should_wipe=*/false, saved.coins_path);
            }
            BOOST_REQUIRE(recovered != nullptr);
            BOOST_REQUIRE(chainstate.ReplayBlocks());
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == recovered->GetBlockHash());
            BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
            BOOST_CHECK(!RootsDB().GetPendingDisconnect());
            BOOST_REQUIRE(RootsDB().GetPublishedTip());
            BOOST_CHECK(*RootsDB().GetPublishedTip() == recovered->GetBlockHash());
            BOOST_CHECK(!RootsDB().ReadTxRoots(carrier_header.nBlockHash, root));
            BOOST_CHECK(!RootsDB().Read(carrier_header.nBlockHash, root));
            const bool keep_parent{mode == "replacement-root-alias" || ancestor_alias};
            BOOST_CHECK_EQUAL(RootsDB().ReadTxRoots(parent_header.nBlockHash, root), keep_parent);
            if (keep_parent) {
                BOOST_CHECK(root.nTxRoot == (ancestor_alias
                    ? checkpoint_header.nTxRoot : parent_header.nTxRoot));
                BOOST_CHECK(root.nReceiptRoot == (ancestor_alias
                    ? checkpoint_header.nReceiptRoot : parent_header.nReceiptRoot));
            }
            BOOST_CHECK_EQUAL(RootsDB().Read(parent_header.nBlockHash, root), keep_parent);
            BOOST_REQUIRE(RootsDB().ReadTxRoots(checkpoint_header.nBlockHash, root));
            BOOST_CHECK(root.nTxRoot == checkpoint_header.nTxRoot);
            BOOST_CHECK(root.nReceiptRoot == checkpoint_header.nReceiptRoot);
            BOOST_CHECK(MintDB().ExistsTx(mint_hash));
            BOOST_CHECK(!MintDB().ExistsTx(unclaimed_hash));
            if (mode != "replacement-root-alias") {
                // Geth can also recover Q; a matching pair must not force P
                // back onto Core just to hide surplus local proof authority.
                chainstate.m_chain.SetTip(*recovered);
                nevm->applied_count = 1;
                nevm->applied_hash = recovered->GetBlockHash();
                std::string error;
                BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
                    nevm->applied_count, nevm->applied_hash, error));
                BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
            }
            BOOST_CHECK(nevm->connected_blocks.empty());
            BOOST_CHECK(nevm->disconnected_blocks.empty());
            chainstate.ResetCoinsViews();
            pnevmtxrootsdb.reset();
            pnevmtxmintdb.reset();
            fs::remove_all(saved.fixture_root);
            if (mode == "repeated-cleanup") {
                CDBWrapper manifest{DBParams{
                    .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
                std::vector<std::string> recovery_roots;
                BOOST_REQUIRE(manifest.Read(std::string{"recovery_roots"}, recovery_roots));
                BOOST_REQUIRE_EQUAL(recovery_roots.size(), 2U);
                for (const auto& path_string : recovery_roots) {
                    const fs::path path{fs::u8path(path_string)};
                    BOOST_REQUIRE(path != m_path_root);
                    BOOST_REQUIRE(path.parent_path() == m_path_root.parent_path());
                    fs::remove_all(path);
                }
            }
        }
    }
#else
    BOOST_TEST_MESSAGE("Skipping subprocess root-crash regression: Boost.Process unavailable");
#endif
}

BOOST_FIXTURE_TEST_CASE(nevm_replay_preserves_alias_with_aligned_published_tip,
                        NEVMRootRollbackSetup)
{
#if defined(HAVE_BOOST_PROCESS) || defined(ENABLE_EXTERNAL_SIGNER)
    const fs::path crash_path{m_path_root / "aligned-publication-alias"};
    BOOST_REQUIRE(fs::create_directories(crash_path));
    RunRootCrashChild(crash_path, "before-aligned-publication-alias-replay");
    RunRootCrashChild(crash_path, "during-aligned-publication-alias-replay");
    const auto saved{ReadRootCrashManifest(crash_path)};
    BOOST_REQUIRE(saved.replacement);
    OpenRootCrashState(saved);
    CNEVMHeader canonical, checkpoint_header, discarded;
    BlockValidationState state;
    BOOST_REQUIRE(GetNEVMData(state, *saved.replacement, canonical));
    BOOST_REQUIRE(GetNEVMData(state, saved.checkpoint, checkpoint_header));
    BOOST_REQUIRE(GetNEVMData(state, saved.carrier, discarded));
    LOCK(::cs_main);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == saved.replacement->GetHash());
    BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
    BOOST_REQUIRE(RootsDB().GetPublishedTip() == saved.replacement->GetHash());
    BOOST_REQUIRE(!RootsDB().GetPendingDisconnect());
    NEVMTxRoot root;
    BOOST_REQUIRE(RootsDB().Read(canonical.nBlockHash, root));
    BOOST_CHECK(root.nTxRoot == canonical.nTxRoot);
    BOOST_CHECK(root.nReceiptRoot == canonical.nReceiptRoot);
    BOOST_CHECK(!RootsDB().Read(discarded.nBlockHash, root));
    BOOST_REQUIRE(RootsDB().Read(checkpoint_header.nBlockHash, root));
    BOOST_CHECK(root.nTxRoot == checkpoint_header.nTxRoot);
    BOOST_CHECK(root.nReceiptRoot == checkpoint_header.nReceiptRoot);

    // This cold startup legitimately takes T==coins/no-D's fast path. It
    // must not depend on a vanished in-memory alias-restoration obligation.
    std::size_t root_writes{0};
    std::size_t coins_syncs{0};
    RootsDB().before_write = [&] { ++root_writes; return true; };
    chainstate.CoinsDB().SetSyncCallbackForTesting([&] { ++coins_syncs; return true; });
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    RootsDB().before_write = {};
    chainstate.CoinsDB().SetSyncCallbackForTesting({});
    BOOST_CHECK_EQUAL(root_writes, 0U);
    BOOST_CHECK_EQUAL(coins_syncs, 0U);
    BOOST_REQUIRE(RootsDB().ReadTxRoots(canonical.nBlockHash, root));
    BOOST_CHECK(root.nTxRoot == canonical.nTxRoot);
    BOOST_CHECK(root.nReceiptRoot == canonical.nReceiptRoot);
    BOOST_CHECK(nevm->connected_blocks.empty());
    BOOST_CHECK(nevm->disconnected_blocks.empty());
    chainstate.ResetCoinsViews();
    pnevmtxrootsdb.reset();
    pnevmtxmintdb.reset();
    fs::remove_all(saved.fixture_root);
    CDBWrapper manifest{DBParams{
        .path = crash_path / "manifest", .cache_bytes = 1U << 20}};
    std::vector<std::string> recovery_roots;
    BOOST_REQUIRE(manifest.Read(std::string{"recovery_roots"}, recovery_roots));
    BOOST_REQUIRE_EQUAL(recovery_roots.size(), 1U);
    const fs::path recovery_root{fs::u8path(recovery_roots.front())};
    BOOST_REQUIRE(recovery_root != m_path_root);
    BOOST_REQUIRE(recovery_root.parent_path() == m_path_root.parent_path());
    fs::remove_all(recovery_root);
#else
    BOOST_TEST_MESSAGE("Skipping subprocess root-crash regression: Boost.Process unavailable");
#endif
}

BOOST_FIXTURE_TEST_CASE(nevm_full_flush_publishes_root_branch_before_coins,
                        NEVMRootRollbackSetup)
{
    PrepareRootDisconnect(/*with_mint=*/true, /*lagging_coins=*/true);
    LOCK(::cs_main);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    const auto previous_published_tip{RootsDB().GetPublishedTip()};
    std::size_t root_writes{0};
    std::size_t coins_writes{0};
    RootsDB().before_write = [&] {
        ++root_writes;
        NEVMTxRoot root;
        BOOST_CHECK(!RootsDB().Read(canonical_header.nBlockHash, root));
        BOOST_CHECK(!RootsDB().Read(orphan_header.nBlockHash, root));
        return false;
    };
    chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
        ++coins_writes;
        return true;
    });
    BlockValidationState failed_state;
    m_node.notifications->m_shutdown_on_fatal_error = false;
    const bool failed_flush{chainstate.FlushStateToDisk(failed_state, FlushStateMode::ALWAYS)};
    m_node.notifications->m_shutdown_on_fatal_error = true;
    m_node.exit_status.store(EXIT_SUCCESS);
    BOOST_CHECK(!failed_flush);
    BOOST_CHECK(failed_state.IsError());
    BOOST_CHECK_EQUAL(root_writes, 1U);
    BOOST_CHECK_EQUAL(coins_writes, 0U);
    BOOST_CHECK(RootsDB().GetPublishedTip() == previous_published_tip);
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == checkpoint->GetHash());
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == carrier.GetHash());
    NEVMTxRoot root;
    BOOST_CHECK(!RootsDB().Read(canonical_header.nBlockHash, root));
    BOOST_CHECK(!RootsDB().Read(orphan_header.nBlockHash, root));

    // Retry the same real flush. The first successful root write publishes T;
    // every root cache batch and the later coins write must observe that T.
    root_writes = 0;
    bool publication_written{false};
    RootsDB().observe_sync = [](bool sync) { BOOST_CHECK(sync); };
    RootsDB().before_write = [&] {
        ++root_writes;
        if (root_writes > 1) {
            uint256 published;
            BOOST_REQUIRE(publication_written);
            BOOST_REQUIRE(RootsDB().Read(uint8_t{'T'}, published));
            BOOST_CHECK(published == carrier.GetHash());
        }
        return true;
    };
    RootsDB().after_write = [&] {
        if (root_writes == 1) {
            uint256 published;
            BOOST_REQUIRE(RootsDB().Read(uint8_t{'T'}, published));
            BOOST_CHECK(published == carrier.GetHash());
            publication_written = true;
        }
    };
    chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
        ++coins_writes;
        BOOST_REQUIRE(publication_written);
        BOOST_REQUIRE_GE(root_writes, 2U);
        BOOST_REQUIRE(RootsDB().GetPublishedTip());
        BOOST_CHECK(*RootsDB().GetPublishedTip() == carrier.GetHash());
        for (const auto* header : {&canonical_header, &orphan_header}) {
            NEVMTxRoot durable;
            BOOST_REQUIRE(RootsDB().Read(header->nBlockHash, durable));
            BOOST_CHECK(durable.nTxRoot == header->nTxRoot);
            BOOST_CHECK(durable.nReceiptRoot == header->nReceiptRoot);
        }
        return true;
    });
    BlockValidationState state;
    const bool flushed{chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS)};
    RootsDB().before_write = {};
    RootsDB().after_write = {};
    RootsDB().observe_sync = {};
    chainstate.CoinsDB().SetWriteBatchCallbackForTesting({});
    BOOST_REQUIRE_MESSAGE(flushed, state.ToString());
    BOOST_CHECK_EQUAL(root_writes, 2U);
    BOOST_CHECK_GT(coins_writes, 0U);
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == carrier.GetHash());
    BOOST_CHECK(chainstate.CoinsDB().HaveCoin(minted_coin));
    BOOST_CHECK(!RootsDB().GetPendingDisconnect());
}

BOOST_FIXTURE_TEST_CASE(nevm_nonmint_local_disconnect_revokes_roots,
                        NEVMRootRollbackSetup)
{
    PrepareRootDisconnect(/*with_mint=*/false);
    // A recently connected parent can still have its root only in RAM.
    // Committing parent coins must also make that surviving authority durable.
    BOOST_REQUIRE(RootsDB().Erase(canonical_header.nBlockHash, /*fSync=*/true));
    RootsDB().FlushDataToCache({{canonical_header.nBlockHash,
        {canonical_header.nTxRoot, canonical_header.nReceiptRoot}}});
    NEVMTxRoot cached_parent;
    BOOST_REQUIRE(!RootsDB().Read(canonical_header.nBlockHash, cached_parent));
    BOOST_REQUIRE(RootsDB().ReadTxRoots(canonical_header.nBlockHash, cached_parent));
    RootsDB().observe_sync = [](bool sync) { BOOST_CHECK(sync); };
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    std::size_t coins_syncs{0};
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
            ++coins_syncs;
            NEVMTxRoot durable_parent;
            BOOST_REQUIRE(RootsDB().Read(canonical_header.nBlockHash, durable_parent));
            BOOST_CHECK(durable_parent.nTxRoot == canonical_header.nTxRoot);
            BOOST_CHECK(durable_parent.nReceiptRoot == canonical_header.nReceiptRoot);
            return true;
        });
    }
    BlockValidationState state;
    BOOST_REQUIRE(DisconnectRootTip(state, /*reverify=*/false));
    LOCK(::cs_main);
    chainstate.CoinsDB().SetSyncCallbackForTesting({});
    BOOST_CHECK_EQUAL(coins_syncs, 1U);
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent->GetHash());
    BOOST_CHECK(!RootsDB().GetPendingDisconnect());
    NEVMTxRoot roots;
    BOOST_CHECK(!RootsDB().ReadTxRoots(orphan_header.nBlockHash, roots));
    BOOST_REQUIRE(RootsDB().Read(canonical_header.nBlockHash, roots));
    BOOST_CHECK(RootsDB().ReadTxRoots(canonical_header.nBlockHash, roots));
    BOOST_CHECK(nevm->disconnected_blocks.empty());
}

BOOST_FIXTURE_TEST_CASE(nevm_root_prepare_failure_preserves_coin_cache,
                        NEVMRootRollbackSetup)
{
    PrepareRootDisconnect();
    RootsDB().before_write = [] { return false; };
    BlockValidationState state;
    BOOST_CHECK(!DisconnectRootTip(state, /*reverify=*/true));
    RootsDB().before_write = {};
    BOOST_CHECK(state.IsError());
    LOCK(::cs_main);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == carrier.GetHash());
    BOOST_CHECK(chainstate.CoinsTip().HaveCoin(minted_coin));
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == carrier.GetHash());
    BOOST_CHECK(chainstate.CoinsDB().HaveCoin(minted_coin));
    BOOST_CHECK(!RootsDB().GetPendingDisconnect());
    NEVMTxRoot roots;
    BOOST_CHECK(RootsDB().ReadTxRoots(orphan_header.nBlockHash, roots));
    BOOST_CHECK(MintDB().ExistsTx(mint_hash));
}

BOOST_FIXTURE_TEST_CASE(nevm_failed_coins_write_shutdown_preserves_recoverable_state,
                        NEVMRootRollbackSetup)
{
    PrepareRootDisconnect(/*with_mint=*/true);
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    const COutPoint restored_input{carrier.vtx[1]->vin[0].prevout};
    LOCK(::cs_main);
    const auto coins_path{chainstate.CoinsDB().StoragePath()};
    BOOST_REQUIRE(coins_path);
    BOOST_REQUIRE(chainstate.CoinsDB().HaveCoin(minted_coin));
    BOOST_REQUIRE(!chainstate.CoinsDB().HaveCoin(restored_input));

    std::size_t coins_writes{0};
    chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
        if (++coins_writes == 1) {
            throw dbwrapper_error("injected transient coins write failure");
        }
        return true;
    });
    BlockValidationState failed_state;
    BOOST_REQUIRE(!DisconnectRootTip(failed_state, /*reverify=*/false));
    BOOST_REQUIRE(failed_state.IsError());
    BOOST_REQUIRE(RootsDB().GetPendingDisconnect());
    BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == carrier.GetHash());
    BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
    BOOST_REQUIRE(chainstate.CoinsDB().HaveCoin(minted_coin));
    BOOST_REQUIRE(!chainstate.CoinsDB().HaveCoin(restored_input));

    // Shutdown retries this very CoinsTip after a runtime failure. A transient
    // WAL append failure does not poison LevelDB, so that retry can succeed.
    // It must preserve the old recovery head or commit every parent coin;
    // publishing a clean parent marker after dropping failed dirty entries
    // prevents startup from detecting and replaying the missing undo writes.
    m_node.notifications->m_shutdown_on_fatal_error = false;
    chainstate.ForceFlushStateToDisk();
    m_node.notifications->m_shutdown_on_fatal_error = true;
    m_node.exit_status.store(EXIT_SUCCESS);
    chainstate.CoinsDB().SetWriteBatchCallbackForTesting({});
    const uint256 recovered_tip{chainstate.CoinsDB().GetBestBlock()};
    BOOST_TEST_MESSAGE("shutdown coins writes=" << coins_writes <<
                       " parent marker=" << (recovered_tip == parent->GetHash()));
    BOOST_REQUIRE(recovered_tip == carrier.GetHash() || recovered_tip == parent->GetHash());
    const bool parent_published{recovered_tip == parent->GetHash()};
    BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(minted_coin), !parent_published);
    BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(restored_input), parent_published);

    // Reopen with no caller cache, as normal startup does. Empty HEADS means
    // ReplayBlocks must trust BEST, so it cannot repair a false-clean marker.
    chainstate.ResetCoinsViews();
    chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                           /*should_wipe=*/false, *coins_path);
    BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == recovered_tip);
    BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(minted_coin), !parent_published);
    BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(restored_input), parent_published);
    BOOST_CHECK(!RootsDB().GetPendingDisconnect());
    BOOST_CHECK(MintDB().ExistsTx(mint_hash));
    chainstate.InitCoinsCache(1U << 23);
    BOOST_REQUIRE(chainstate.LoadChainTip());
}

BOOST_FIXTURE_TEST_CASE(nevm_verification_disconnect_keeps_root_authority,
                        NEVMRootRollbackSetup)
{
    PrepareRootDisconnect(/*with_mint=*/false);
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    LOCK(::cs_main);
    CCoinsViewCache private_view{&chainstate.CoinsTip()};
    NEVMMintTxSet mints;
    std::vector<uint256> roots_to_remove;
    std::vector<std::pair<uint256, uint32_t>> txids;
    BOOST_REQUIRE(chainstate.DisconnectBlock(
        carrier, chainman.ActiveTip(), private_view, mints, roots_to_remove,
        txids, /*bReverify=*/false, /*bReplay=*/false,
        /*bUpdateSpecialTxState=*/false) == DISCONNECT_OK);
    BOOST_CHECK(private_view.GetBestBlock() == parent->GetHash());
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == carrier.GetHash());
    BOOST_CHECK(!RootsDB().GetPendingDisconnect());
    NEVMTxRoot roots;
    BOOST_CHECK(RootsDB().ReadTxRoots(orphan_header.nBlockHash, roots));
    BOOST_CHECK(nevm->disconnected_blocks.empty());
}
// SYSCOIN END: Exercise real process loss and empty-HEADS startup recovery.

BOOST_FIXTURE_TEST_CASE(nevm_coins_replay_recovers_partial_forward_flush_locally,
                        CoinsNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const uint256 old_head{
        WITH_LOCK(::cs_main, return chainman.ActiveTip()->GetBlockHash())};
    const auto first{MineNEVMBlock()};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainstate.CoinsTip().Flush());
    }
    const auto second{MineNEVMBlock()};
    const COutPoint first_coin{first->vtx[0]->GetHash(), 0};
    const COutPoint second_coin{second->vtx[0]->GetHash(), 0};
    {
        LOCK(::cs_main);
        // The interrupted batch has written the first block's coins but not
        // the second block, so recovery must support both idempotent replay
        // and previously unapplied UTXO additions in the same pass.
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == first->GetHash());
        BOOST_REQUIRE(chainstate.CoinsDB().HaveCoin(first_coin));
        BOOST_REQUIRE(!chainstate.CoinsDB().HaveCoin(second_coin));
    }
    BOOST_REQUIRE(pnevmtxrootsdb != nullptr);
    BOOST_REQUIRE(pnevmtxmintdb != nullptr);
    CNEVMHeader first_header, second_header;
    BlockValidationState first_state, second_state;
    BOOST_REQUIRE(GetNEVMData(first_state, *first, first_header));
    BOOST_REQUIRE(GetNEVMData(second_state, *second, second_header));
    BOOST_REQUIRE(pnevmtxrootsdb->FlushErase(
        {first_header.nBlockHash, second_header.nBlockHash}));
    const uint256 retained_mint{RecoveryFixtureHash(90'001)};
    pnevmtxmintdb->FlushDataToCache({retained_mint});
    BOOST_REQUIRE(pnevmtxmintdb->FlushCacheToDisk());

    PrepareInterruptedFlush(second->GetHash(), old_head);
    nevm->connected_blocks.clear();
    nevm->disconnected_blocks.clear();
    nevm->connect_error = "nevm-not-connected";
    nevm->disconnect_error = "nevm-not-connected";
    const auto info_queries{nevm->block_info_queries};
    const auto flush_queries{nevm->flush_requests};
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    CheckRecoveredTip(second->GetHash());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainstate.CoinsDB().HaveCoin(first_coin));
        BOOST_CHECK(chainstate.CoinsDB().HaveCoin(second_coin));
    }
    NEVMTxRoot first_roots, second_roots;
    BOOST_REQUIRE(pnevmtxrootsdb->ReadTxRoots(first_header.nBlockHash, first_roots));
    BOOST_REQUIRE(pnevmtxrootsdb->ReadTxRoots(second_header.nBlockHash, second_roots));
    BOOST_CHECK(first_roots.nTxRoot == first_header.nTxRoot);
    BOOST_CHECK(first_roots.nReceiptRoot == first_header.nReceiptRoot);
    BOOST_CHECK(second_roots.nTxRoot == second_header.nTxRoot);
    BOOST_CHECK(second_roots.nReceiptRoot == second_header.nReceiptRoot);
    BOOST_CHECK(pnevmtxmintdb->ExistsTx(retained_mint));
    BOOST_CHECK(nevm->connected_blocks.empty());
    BOOST_CHECK(nevm->disconnected_blocks.empty());
    BOOST_CHECK_EQUAL(nevm->block_info_queries, info_queries);
    BOOST_CHECK_EQUAL(nevm->flush_requests, flush_queries);
    BOOST_CHECK(fNEVMConnection);
}

BOOST_FIXTURE_TEST_CASE(nevm_coins_replay_recovers_fork_locally,
                        CoinsNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto old_first{MineNEVMBlock()};
    const auto old_second{MineNEVMBlock()};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainstate.CoinsTip().Flush());
    }
    CBlockIndex* old_branch{
        WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(
            old_first->GetHash()))};
    BOOST_REQUIRE(old_branch != nullptr);
    BlockValidationState invalidate_state;
    // SYSCOIN: Manufacture a partial old-branch DB flush for ReplayBlocks.
    // Disable the fixture's external-engine context during setup, as RewindCore
    // does; a real local-only disconnect now also revokes roots and syncs coins.
    {
        struct RestoreNEVMConnection {
            const bool previous{fNEVMConnection};
            ~RestoreNEVMConnection() { fNEVMConnection = previous; }
        } restore;
        fNEVMConnection = false;
        BOOST_REQUIRE_MESSAGE(chainstate.InvalidateBlock(
            invalidate_state, old_branch, /*bReverify=*/false),
            invalidate_state.ToString());
    }
    BOOST_REQUIRE_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), 100);
    const auto new_first{MineNEVMBlock()};
    const auto new_second{MineNEVMBlock()};
    {
        LOCK(::cs_main);
        // Both heads of the interrupted flush represent validated branches.
        // Reconsider the old branch after selecting the new one; recovery
        // applies the recorded target without running best-chain activation.
        chainstate.ResetBlockFailureFlags(old_branch);
        BOOST_REQUIRE(old_branch->IsValid(BLOCK_VALID_SCRIPTS));
    }
    const COutPoint old_coin{old_second->vtx[0]->GetHash(), 0};
    const COutPoint new_coin{new_second->vtx[0]->GetHash(), 0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == old_second->GetHash());
        BOOST_REQUIRE(chainstate.CoinsDB().HaveCoin(old_coin));
        BOOST_REQUIRE(!chainstate.CoinsDB().HaveCoin(new_coin));
    }
    BOOST_REQUIRE(pnevmtxrootsdb != nullptr);
    std::array<CNEVMHeader, 4> headers;
    const std::array blocks{old_first, old_second, new_first, new_second};
    for (std::size_t i{0}; i < blocks.size(); ++i) {
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, *blocks[i], headers[i]));
    }
    BOOST_REQUIRE(pnevmtxrootsdb->FlushErase(
        {headers[2].nBlockHash, headers[3].nBlockHash}));
    NEVMTxRoot old_roots;
    BOOST_REQUIRE(pnevmtxrootsdb->ReadTxRoots(headers[1].nBlockHash, old_roots));
    // SYSCOIN: The same restart can have both a pending root revocation and
    // interrupted coins batches. The recovered coins branch must be durable
    // before root cleanup/restoration and retirement of its recovery record.
    BOOST_REQUIRE(pnevmtxrootsdb->BeginDisconnect(NEVMRootDisconnect{
        old_second->GetHash(), headers[1].nBlockHash,
        headers[1].nTxRoot, headers[1].nReceiptRoot}));

    PrepareInterruptedFlush(new_second->GetHash(), old_second->GetHash());
    nevm->connected_blocks.clear();
    nevm->disconnected_blocks.clear();
    // Model an already-aligned external engine that rejects replay of older
    // canonical blocks and would reject disconnects from the abandoned fork.
    nevm->connect_error = "nevm-historical-duplicate";
    nevm->disconnect_error = "nevm-disconnect-wrong-branch";
    const auto applied_count{nevm->applied_count};
    const auto applied_hash{nevm->applied_hash};
    const auto info_queries{nevm->block_info_queries};
    const auto flush_queries{nevm->flush_requests};
    std::size_t recovery_syncs{0};
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
            ++recovery_syncs;
            BOOST_REQUIRE(pnevmtxrootsdb->GetPendingDisconnect());
            return true;
        });
    }
    BOOST_REQUIRE(chainstate.ReplayBlocks());
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetSyncCallbackForTesting({});
    }
    BOOST_CHECK_EQUAL(recovery_syncs, 1U);
    BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
    CheckRecoveredTip(new_second->GetHash());
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(old_coin));
        BOOST_CHECK(chainstate.CoinsDB().HaveCoin(new_coin));
    }
    for (std::size_t i{0}; i < headers.size(); ++i) {
        NEVMTxRoot roots;
        const bool found{pnevmtxrootsdb->ReadTxRoots(headers[i].nBlockHash, roots)};
        BOOST_CHECK_EQUAL(found, i >= 2);
        if (found) {
            BOOST_CHECK(roots.nTxRoot == headers[i].nTxRoot);
            BOOST_CHECK(roots.nReceiptRoot == headers[i].nReceiptRoot);
            NEVMTxRoot durable_roots;
            BOOST_REQUIRE(pnevmtxrootsdb->Read(headers[i].nBlockHash, durable_roots));
            BOOST_CHECK(durable_roots.nTxRoot == headers[i].nTxRoot);
            BOOST_CHECK(durable_roots.nReceiptRoot == headers[i].nReceiptRoot);
        }
    }
    BOOST_CHECK(nevm->connected_blocks.empty());
    BOOST_CHECK(nevm->disconnected_blocks.empty());
    BOOST_CHECK_EQUAL(nevm->block_info_queries, info_queries);
    BOOST_CHECK_EQUAL(nevm->flush_requests, flush_queries);
    BOOST_CHECK_EQUAL(nevm->applied_count, applied_count);
    BOOST_CHECK(nevm->applied_hash == applied_hash);
    BOOST_CHECK(fNEVMConnection);
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_clears_only_at_exact_tip,
                        StartupNEVMRecoverySetup)
{
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    Chainstate& chainstate{chainman.ActiveChainstate()};
    const CBlockIndex* replay_tip{
        WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    BOOST_REQUIRE(replay_tip != nullptr);
    BOOST_REQUIRE_EQUAL(replay_tip->nHeight, 100);

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

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_commits_each_bounded_batch,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    std::vector<uint256> expected_blocks;
    BOOST_REQUIRE(governance != nullptr);
    struct ClearGovernanceReadiness {
        ~ClearGovernanceReadiness() { governance->ObserveChainTip(nullptr); }
    } clear_governance_readiness;
    // More than one replay batch, including a partial final batch.
    for (int i{0}; i < 70; ++i) {
        // Like the inherited bootstrap miner, provide the empty governance
        // fixture's exact parent state across regtest superblock heights.
        const CBlockIndex* parent{
            WITH_LOCK(::cs_main, return chainman.ActiveTip())};
        BOOST_REQUIRE(parent != nullptr);
        BOOST_REQUIRE(governance_tests::PublishGovernanceReadyForTest(
            *governance, *parent));
        expected_blocks.push_back(
            MineNEVMBlock(/*forward_to_nevm=*/false)->GetHash());
    }
    governance->ObserveChainTip(nullptr);
    const CBlockIndex* target{
        WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    BOOST_REQUIRE(target != nullptr);
    BOOST_REQUIRE_EQUAL(nevm->applied_count, 0U);
    BOOST_REQUIRE(nevm->connected_blocks.empty());
    nevm->buffer_connects = true;

    std::size_t finalizations{0};
    const auto finalize = [&] {
        AssertMainLockHeldForTest();
        ++finalizations;
        BOOST_CHECK_EQUAL(nevm->applied_count, expected_blocks.size());
        BOOST_CHECK(nevm->applied_hash == target->GetBlockHash());
        BOOST_REQUIRE(nevm->last_reported_pair.has_value());
        BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, expected_blocks.size());
        BOOST_CHECK(nevm->last_reported_pair->hash == target->GetBlockHash());
        BOOST_CHECK(!nevm->buffered_pair.has_value());
        return true;
    };
    bool complete{false};
    std::string error;
    BOOST_REQUIRE_MESSAGE(ReplayDeferredForTest(
        chainstate, target->nHeight, target->GetBlockHash(),
        finalize, complete, error), error);
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(finalizations, 0U);
    BOOST_CHECK_EQUAL(nevm->applied_count, 64U);
    BOOST_CHECK(nevm->applied_hash == expected_blocks[63]);
    BOOST_CHECK(!nevm->buffered_pair.has_value());
    BOOST_CHECK(error.empty());

    BOOST_REQUIRE_MESSAGE(ReplayDeferredForTest(
        chainstate, target->nHeight, target->GetBlockHash(),
        finalize, complete, error), error);
    BOOST_CHECK(complete);
    BOOST_CHECK_EQUAL(finalizations, 1U);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(nevm->connected_blocks == expected_blocks);
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_flushes_accepted_prefix_before_cursor,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    nevm->buffer_connects = true;
    const auto first{MineNEVMBlock()};
    const auto second{MineNEVMBlock()};
    const auto target{MineNEVMBlock(/*forward_to_nevm=*/false)};
    BOOST_REQUIRE_EQUAL(nevm->applied_count, 0U);
    BOOST_REQUIRE(nevm->buffered_pair.has_value());
    BOOST_REQUIRE_EQUAL(nevm->buffered_pair->count, 2U);

    bool finalized{false};
    bool complete{false};
    std::string error;
    BOOST_REQUIRE_MESSAGE(ReplayDeferredForTest(
        chainman.ActiveChainstate(),
        WITH_LOCK(::cs_main, return chainman.ActiveHeight()), target->GetHash(),
        [&] {
            finalized = true;
            BOOST_CHECK_EQUAL(nevm->applied_count, 3U);
            BOOST_CHECK(nevm->applied_hash == target->GetHash());
            BOOST_REQUIRE(nevm->last_reported_pair.has_value());
            BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 3U);
            BOOST_CHECK(nevm->last_reported_pair->hash == target->GetHash());
            return true;
        },
        complete, error), error);
    BOOST_CHECK(complete);
    BOOST_CHECK(finalized);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!nevm->buffered_pair.has_value());
    const std::vector<uint256> expected_blocks{
        first->GetHash(), second->GetHash(), target->GetHash()};
    BOOST_CHECK(nevm->connected_blocks == expected_blocks);
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_waits_for_flush_availability,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto target{MineNEVMBlock(/*forward_to_nevm=*/false)};
    const int target_height{
        WITH_LOCK(::cs_main, return chainman.ActiveHeight())};
    nevm->buffer_connects = true;
    nevm->flush_available = false;
    bool finalized{false};
    const auto finalize = [&] {
        finalized = true;
        BOOST_CHECK(nevm->applied_hash == target->GetHash());
        return true;
    };
    bool complete{false};
    std::string error;
    BOOST_CHECK(!ReplayDeferredForTest(
        chainman.ActiveChainstate(), target_height, target->GetHash(),
        finalize, complete, error));
    BOOST_CHECK(!complete);
    BOOST_CHECK(!finalized);
    BOOST_CHECK(!error.empty());
    BOOST_CHECK_EQUAL(nevm->flush_requests, 1U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);
    BOOST_CHECK(nevm->connected_blocks.empty());

    nevm->flush_available = true;
    BOOST_REQUIRE_MESSAGE(ReplayDeferredForTest(
        chainman.ActiveChainstate(), target_height, target->GetHash(),
        finalize, complete, error), error);
    BOOST_CHECK(complete);
    BOOST_CHECK(finalized);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_replay_requires_reported_commit_pair,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto target{MineNEVMBlock(/*forward_to_nevm=*/false)};
    const int target_height{
        WITH_LOCK(::cs_main, return chainman.ActiveHeight())};
    nevm->buffer_connects = true;
    // A successful flush acknowledgement cannot substitute for the applied
    // pair when the endpoint's status view has not caught up yet.
    nevm->reported_pair_override = StartupNEVMSubscriber::AppliedPair{0, {}};
    bool finalized{false};
    const auto finalize = [&] {
        finalized = true;
        BOOST_REQUIRE(nevm->last_reported_pair.has_value());
        BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 1U);
        BOOST_CHECK(nevm->last_reported_pair->hash == target->GetHash());
        return true;
    };
    bool complete{false};
    std::string error;
    BOOST_CHECK(!ReplayDeferredForTest(
        chainman.ActiveChainstate(), target_height, target->GetHash(),
        finalize, complete, error));
    BOOST_CHECK(!complete);
    BOOST_CHECK(!finalized);
    BOOST_CHECK_EQUAL(error, "deferred-nevm-commit-pair-mismatch");
    BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 1U);

    nevm->reported_pair_override.reset();
    BOOST_REQUIRE_MESSAGE(ReplayDeferredForTest(
        chainman.ActiveChainstate(), target_height, target->GetHash(),
        finalize, complete, error), error);
    BOOST_CHECK(complete);
    BOOST_CHECK(finalized);
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 1U);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_ahead_pair_recovers_without_duplicate_connects,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    MineNEVMBlock();
    MineNEVMBlock();
    const auto target{MineNEVMBlock()};
    BOOST_REQUIRE_EQUAL(nevm->applied_count, 3U);
    BOOST_REQUIRE_EQUAL(nevm->connected_blocks.size(), 3U);

    // Model a restart with Core's coins tip behind the pair Geth retained.
    // The same stored blocks remain available to ActivateBestChain.
    RewindCore(101);
    BOOST_REQUIRE(!chainman.IsInitialBlockDownload());
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, nevm->applied_hash, error));
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(chainman.MaybeCompleteNEVMStartupPair(error));
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    }
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK_THROW(MakeNEVMBlock(), std::runtime_error);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);

    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(
        chainman.ActiveChainstate().ActivateBestChain(state),
        state.ToString());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                target->GetHash());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main,
        return chainman.ActiveChainstate().CoinsTip().GetBestBlock()) ==
                target->GetHash());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
    BOOST_CHECK(nevm->disconnected_blocks.empty());
    BOOST_CHECK_GT(nevm->block_info_queries, 0U);
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(!chainman.IsInitialBlockDownload());

    // Recovery suppresses only the already-applied prefix. A subsequent
    // block follows the ordinary external validation and notification path.
    const auto next{MineNEVMBlock()};
    BOOST_REQUIRE_EQUAL(nevm->connected_blocks.size(), 4U);
    BOOST_CHECK(nevm->connected_blocks.back() == next->GetHash());
    BOOST_CHECK_EQUAL(nevm->applied_count, 4U);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_requires_fresh_exact_completion,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    MineNEVMBlock();
    const auto previous{MineNEVMBlock()};
    const auto target{MineNEVMBlock()};
    RewindCore(102);
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            3, target->GetHash(), error));

        // A successful historical validation check does not publish a tip
        // or establish that Core has recovered the external engine's pair.
        auto& chainstate{chainman.ActiveChainstate()};
        CCoinsViewCache view{&chainstate.CoinsTip()};
        BlockValidationState check_state;
        BOOST_REQUIRE(chainstate.ConnectBlock(
            *target, check_state,
            chainman.m_blockman.LookupBlockIndex(target->GetHash()),
            view, /*fJustCheck=*/true));
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() ==
                    previous->GetHash());
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
    }
    nevm->block_info_error = "startup-test-status-unavailable";
    BlockValidationState state;
    const bool activated{
        chainman.ActiveChainstate().ActivateBestChain(state)};
    BOOST_CHECK(activated);
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                target->GetHash());
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
    BOOST_CHECK_GT(nevm->block_info_queries, 0U);

    // The production import caller treats an ABC error as fatal. Pending
    // status must leave it free to finish and release the acquisition guard.
    m_node.notifications->m_shutdown_on_fatal_error = false;
    node::ImportBlocks(chainman, {}, nullptr, deterministicMNManager,
                       activeMasternodeManager, g_wallet_init_interface, m_node);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    BOOST_CHECK(!chainman.m_blockman.LoadingBlocks());
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());

    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.MaybeCompleteNEVMStartupPair(error));
        BOOST_CHECK(error.empty());
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());

        nevm->block_info_error.clear();
        nevm->applied_hash = previous->GetHash();
        BOOST_CHECK(!chainman.MaybeCompleteNEVMStartupPair(error));
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());

        nevm->applied_hash = target->GetHash();
        nevm->applied_count = 2;
        BOOST_CHECK(!chainman.MaybeCompleteNEVMStartupPair(error));
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    }
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    // A stopped startup worker must perform no external status request.
    const auto queries_before_interrupt{nevm->block_info_queries};
    m_node.kernel->interrupt();
    BlockValidationState interrupted_state;
    BOOST_CHECK(chainman.RetryNEVMStartupPair(interrupted_state));
    BOOST_CHECK_EQUAL(nevm->block_info_queries, queries_before_interrupt);
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    m_node.kernel->interrupt.reset();

    nevm->applied_count = 3;
    BlockValidationState retry_state;
    BOOST_REQUIRE(chainman.RetryNEVMStartupPair(retry_state));
    BOOST_CHECK(retry_state.IsValid());
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK((chainman.ActiveTip()->nStatus & BLOCK_FAILED_MASK) == 0);
    }
    BOOST_CHECK(!chainman.IsInitialBlockDownload());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_inside_known_suffix_resumes_delivery,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    MineNEVMBlock();
    MineNEVMBlock();
    const auto applied{MineNEVMBlock()};
    const auto next{MineNEVMBlock()};
    // Core may already have the following block available on disk even
    // though Geth's retained applied pair ends one block earlier.
    nevm->applied_count = 3;
    nevm->applied_hash = applied->GetHash();
    nevm->connected_blocks.resize(3);
    RewindCore(101);
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, nevm->applied_hash, error));
    }
    nevm->block_info_error = "startup-test-status-unavailable";
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(
        chainman.ActiveChainstate().ActivateBestChain(state),
        state.ToString());
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                applied->GetHash());
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);

    BlockValidationState pending_state;
    BOOST_REQUIRE(chainman.RetryNEVMStartupPair(pending_state));
    BOOST_CHECK(pending_state.IsValid());
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);

    nevm->block_info_error.clear();
    BlockValidationState retry_state;
    BOOST_REQUIRE(chainman.RetryNEVMStartupPair(retry_state));
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                next->GetHash());
    BOOST_REQUIRE_EQUAL(nevm->connected_blocks.size(), 4U);
    BOOST_CHECK(nevm->connected_blocks.back() == next->GetHash());
    BOOST_CHECK_EQUAL(nevm->applied_count, 4U);
    BOOST_CHECK_GT(nevm->block_info_queries, 0U);
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(!chainman.IsInitialBlockDownload());
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_rejects_other_branch_as_local_error,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto first{MineNEVMBlock()};
    // Both children are ordinary valid templates built on the same parent.
    const auto alternative{MakeNEVMBlock()};
    const auto second{MineNEVMBlock()};
    BOOST_REQUIRE(alternative->GetHash() != second->GetHash());
    const auto target{MineNEVMBlock()};
    RewindCore(101);

    std::string error;
    auto& chainstate{chainman.ActiveChainstate()};
    LOCK2(::cs_main, chainstate.MempoolMutex());
    BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
        3, target->GetHash(), error));
    CBlockIndex alternative_index{alternative->GetBlockHeader()};
    const uint256 alternative_hash{alternative->GetHash()};
    alternative_index.phashBlock = &alternative_hash;
    alternative_index.nHeight = 102;
    alternative_index.pprev = chainman.ActiveTip();
    alternative_index.BuildSkip();
    const auto original_status{alternative_index.nStatus};
    CCoinsViewCache view{&chainstate.CoinsTip()};
    BlockValidationState state;
    BOOST_CHECK(!chainstate.ConnectBlock(
        *alternative, state, &alternative_index, view));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK(view.GetBestBlock() == first->GetHash());
    BOOST_CHECK_EQUAL(alternative_index.nStatus, original_status);
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());

    BlockValidationState disconnect_state;
    BOOST_CHECK(!chainstate.DisconnectTip(disconnect_state, nullptr));
    BOOST_CHECK(disconnect_state.IsError());
    BOOST_CHECK(!disconnect_state.IsInvalid());
    BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == first->GetHash());
    BOOST_CHECK(nevm->disconnected_blocks.empty());
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_waits_before_switching_to_higher_work_sibling,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto branches{PrepareCompetingStartupPair()};
    nevm->block_info_error = "startup-test-status-unavailable";
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*branches.applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
    }
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state), state.ToString());
    BOOST_CHECK(state.IsValid());
    const auto check_waiting = [&] {
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(nevm->connected_blocks.empty());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == branches.applied->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == branches.applied->GetHash());
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
    };
    check_waiting();
    BlockValidationState waiting_state;
    BOOST_REQUIRE_MESSAGE(chainman.RetryNEVMStartupPair(waiting_state), waiting_state.ToString());
    BOOST_CHECK(waiting_state.IsValid());
    check_waiting();

    nevm->block_info_error.clear();
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(chainman.RetryNEVMStartupPair(retry_state), retry_state.ToString());
    BOOST_CHECK(retry_state.IsValid());
    CheckCompetingStartupPairCompleted(branches);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_exact_completion_resumes_fork_choice_in_same_call,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto branches{PrepareCompetingStartupPair()};
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state), state.ToString());
    BOOST_CHECK(state.IsValid());
    CheckCompetingStartupPairCompleted(branches);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_missing_body_waits_despite_higher_work_sibling,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto branches{PrepareCompetingStartupPair(/*have_applied_body=*/false)};
    const auto check_waiting = [&] {
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(nevm->connected_blocks.empty());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == branches.fork->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == branches.fork->GetHash());
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(branches.sibling_tip_index), 1U);
    };
    BlockValidationState waiting_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(waiting_state), waiting_state.ToString());
    BOOST_CHECK(waiting_state.IsValid());
    check_waiting();
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(chainman.RetryNEVMStartupPair(retry_state), retry_state.ToString());
    BOOST_CHECK(retry_state.IsValid());
    check_waiting();

    {
        LOCK(::cs_main);
        BlockValidationState accept_state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            branches.applied, accept_state, nullptr, /*fRequested=*/true,
            /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
            accept_state.ToString());
        BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*branches.applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*branches.sibling_tip_index));
    }
    BlockValidationState recovery_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(recovery_state), recovery_state.ToString());
    BOOST_CHECK(recovery_state.IsValid());
    CheckCompetingStartupPairCompleted(branches);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_advances_available_prefix_before_missing_body,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto fork{MineNEVMBlock()};
    const auto prefix{MakeNEVMBlock()};
    const auto sibling{MineNEVMBlock(/*forward_to_nevm=*/false)};
    CBlock applied_block{*MakeNEVMBlock()};
    BOOST_REQUIRE_EQUAL(applied_block.vtx.size(), 1U);
    BOOST_REQUIRE_LT(103, chainman.GetConsensus().DIP0003Height);
    BOOST_REQUIRE_EQUAL(prefix->nTime, sibling->nTime);
    BOOST_REQUIRE_EQUAL(prefix->nBits, sibling->nBits);
    // This unused height-103 template has a unique mock NEVM payload and
    // only a height-bound coinbase; reparenting avoids manipulating candidates.
    applied_block.hashPrevBlock = prefix->GetHash();
    applied_block.fChecked = false;
    applied_block.nNonce = 0;
    while (!CheckProofOfWork(
        applied_block.GetHash(), applied_block.nBits, chainman.GetConsensus())) {
        ++applied_block.nNonce;
    }
    const auto applied{std::make_shared<const CBlock>(std::move(applied_block))};
    const auto sibling_second{MineNEVMBlock(/*forward_to_nevm=*/false)};
    const auto sibling_tip{MineNEVMBlock(/*forward_to_nevm=*/false)};
    BOOST_REQUIRE(applied->vchNEVMBlockData != sibling_second->vchNEVMBlockData);
    RewindCore(101);

    BlockValidationState header_state;
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
        {prefix->GetBlockHeader(), applied->GetBlockHeader()},
        /*min_pow_checked=*/true, header_state), header_state.ToString());
    CBlockIndex* prefix_index{nullptr};
    CBlockIndex* applied_index{nullptr};
    CBlockIndex* sibling_tip_index{nullptr};
    {
        LOCK(::cs_main);
        BlockValidationState accept_state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            prefix, accept_state, &prefix_index, /*fRequested=*/true,
            /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
            accept_state.ToString());
        applied_index = chainman.m_blockman.LookupBlockIndex(applied->GetHash());
        sibling_tip_index = chainman.m_blockman.LookupBlockIndex(sibling_tip->GetHash());
        BOOST_REQUIRE(prefix_index != nullptr);
        BOOST_REQUIRE(applied_index != nullptr);
        BOOST_REQUIRE(sibling_tip_index != nullptr);
        BOOST_REQUIRE_EQUAL(prefix_index->nHeight, 102);
        BOOST_REQUIRE_EQUAL(applied_index->nHeight, 103);
        BOOST_REQUIRE_EQUAL(sibling_tip_index->nHeight, 104);
        BOOST_REQUIRE(applied_index->pprev == prefix_index);
        BOOST_REQUIRE(sibling_tip_index->nChainWork > applied_index->nChainWork);
        BOOST_REQUIRE(!(applied_index->nStatus & BLOCK_HAVE_DATA));
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(prefix_index), 1U);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(applied_index), 0U);
        BOOST_REQUIRE_EQUAL(chainstate.setBlockIndexCandidates.count(sibling_tip_index), 1U);
        nevm->applied_count = 3;
        nevm->applied_hash = applied->GetHash();
        nevm->connected_blocks.clear();
        nevm->disconnected_blocks.clear();
        std::string error;
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, nevm->applied_hash, error));
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == fork->GetHash());
        BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*prefix_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*sibling_tip_index));
    }
    const auto queries_before{nevm->block_info_queries};
    const auto check_waiting = [&] {
        BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
        BOOST_CHECK(nevm->connected_blocks.empty());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        BOOST_CHECK_EQUAL(nevm->block_info_queries, queries_before);
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == prefix->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == prefix->GetHash());
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*sibling_tip_index));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(sibling_tip_index), 1U);
    };
    BlockValidationState progress_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(progress_state), progress_state.ToString());
    BOOST_CHECK(progress_state.IsValid());
    check_waiting();
    BlockValidationState waiting_state;
    BOOST_REQUIRE_MESSAGE(chainman.RetryNEVMStartupPair(waiting_state), waiting_state.ToString());
    BOOST_CHECK(waiting_state.IsValid());
    check_waiting();

    {
        LOCK(::cs_main);
        BlockValidationState accept_state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            applied, accept_state, nullptr, /*fRequested=*/true,
            /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
            accept_state.ToString());
        BOOST_CHECK(chainstate.IsCurrentMostWorkBranch(*applied_index));
        BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*sibling_tip_index));
    }
    BlockValidationState recovery_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(recovery_state), recovery_state.ToString());
    BOOST_CHECK(recovery_state.IsValid());
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(nevm->disconnected_blocks ==
                (std::vector<uint256>{applied->GetHash(), prefix->GetHash()}));
    BOOST_CHECK(nevm->connected_blocks ==
                (std::vector<uint256>{sibling->GetHash(), sibling_second->GetHash(), sibling_tip->GetHash()}));
    BOOST_REQUIRE(nevm->last_reported_pair.has_value());
    BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 3U);
    BOOST_CHECK(nevm->last_reported_pair->hash == applied->GetHash());
    BOOST_CHECK_EQUAL(nevm->applied_count, 4U);
    BOOST_CHECK(nevm->applied_hash == sibling_tip->GetHash());
    LOCK(::cs_main);
    BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == sibling_tip->GetHash());
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == sibling_tip->GetHash());
    BOOST_CHECK_EQUAL(prefix_index->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK_EQUAL(applied_index->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK_EQUAL(sibling_tip_index->nStatus & BLOCK_FAILED_MASK, 0U);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_respects_btcc_receipt_quarantine,
                        StartupNEVMRecoverySetup)
{
    CheckCompetingStartupPairQuarantine(/*payment_audit=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_respects_payment_receipt_quarantine,
                        StartupNEVMRecoverySetup)
{
    CheckCompetingStartupPairQuarantine(/*payment_audit=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_pair_preserves_matched_behind_and_zero_status,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto first{MineNEVMBlock()};
    const auto second{MineNEVMBlock()};
    const auto third{MineNEVMBlock()};
    std::string error;
    LOCK(::cs_main);
    BOOST_CHECK(chainman.InitializeNEVMStartupPair(3, third->GetHash(), error));
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.InitializeNEVMStartupPair(2, second->GetHash(), error));
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.InitializeNEVMStartupPair(0, uint256{}, error));
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());

    BOOST_CHECK(!chainman.InitializeNEVMStartupPair(0, first->GetHash(), error));
    BOOST_CHECK(!chainman.InitializeNEVMStartupPair(1, uint256{}, error));
    BOOST_CHECK(!chainman.InitializeNEVMStartupPair(2, first->GetHash(), error));
    BOOST_CHECK(!chainman.InitializeNEVMStartupPair(
        std::numeric_limits<uint64_t>::max(), third->GetHash(), error));
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 3U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_unknown_ahead_pair_waits_for_headers,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    const auto first{MineNEVMBlock()};
    const auto second{MineNEVMBlock()};
    MineNEVMBlock();
    const auto future{MakeNEVMBlock()};
    const auto delivered_before{nevm->connected_blocks.size()};
    nevm->applied_count = 4;
    nevm->applied_hash = future->GetHash();
    RewindCore(101);

    // A crash can also leave the paired block's index entry unflushed.
    // A local status pair whose header is unavailable must keep recovery
    // open without treating another available branch as already applied.
    const uint256 unavailable_hash{future->GetHash()};
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.m_blockman.LookupBlockIndex(unavailable_hash) ==
                      nullptr);
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, unavailable_hash, error));
        const CBlockIndex* available{
            chainman.m_blockman.LookupBlockIndex(second->GetHash())};
        BOOST_REQUIRE(available != nullptr);
        BOOST_CHECK(!chainman.CheckNEVMStartupConnect(*available, error));
        BOOST_CHECK(!error.empty());
    }
    BlockValidationState state;
    BOOST_REQUIRE(chainman.ActiveChainstate().ActivateBestChain(state));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                first->GetHash());
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), delivered_before);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);

    // Ordinary block receipt supplies the missing header and resumes the
    // stored suffix. The retained pair is rechecked after Core reaches it.
    BOOST_REQUIRE(chainman.ProcessNewBlock(future, true, true, nullptr));
    BOOST_CHECK(WITH_LOCK(
        ::cs_main, return chainman.ActiveTip()->GetBlockHash()) ==
                future->GetHash());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), delivered_before);
    BOOST_CHECK_GT(nevm->block_info_queries, 0U);
    BOOST_CHECK(!chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(!chainman.IsInitialBlockDownload());
}

BOOST_FIXTURE_TEST_CASE(nevm_startup_bootstrap_pair_activates_only_genesis,
                        FreshNEVMStartupSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    node::ChainstateLoadOptions options;
    options.mempool = m_node.mempool.get();
    options.block_tree_db_in_memory = true;
    options.coins_db_in_memory = true;
    options.connman = m_node.connman.get();
    options.banman = m_node.banman.get();
    options.peerman = m_node.peerman.get();
    const auto [status, load_error]{
        node::LoadChainstate(chainman, m_cache_sizes, options)};
    BOOST_REQUIRE_MESSAGE(status == node::ChainstateLoadStatus::SUCCESS,
                          load_error.original);

    const auto blocks{CreateBlockChain(1, Params())};
    const uint256 genesis_hash{chainman.GetConsensus().hashGenesisBlock};
    CBlockIndex* indexed_child{nullptr};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() == nullptr);
        BOOST_REQUIRE(chainman.ActiveChainstate().CoinsTip().GetBestBlock().IsNull());
        // Restore an already-stored candidate without activating it, as
        // block-index loading can do before an empty coins state is rebuilt.
        // The live AcceptBlock path requires genesis to be active already.
        BlockValidationState block_state;
        BOOST_REQUIRE(CheckBlock(*blocks.front(), block_state,
                                 chainman.GetConsensus()));
        const FlatFilePos pos{chainman.m_blockman.SaveBlockToDisk(
            *blocks.front(), 1, nullptr)};
        BOOST_REQUIRE(!pos.IsNull());
        indexed_child = chainman.m_blockman.AddToBlockIndex(
            *blocks.front(), chainman.m_best_header);
        BOOST_REQUIRE(indexed_child != nullptr);
        chainman.ReceivedBlockTransactions(*blocks.front(), indexed_child, pos);
        std::string error;
        nevm->applied_count = 1;
        nevm->applied_hash = InsecureRand256();
        BOOST_REQUIRE(chainman.InitializeNEVMStartupPair(
            nevm->applied_count, nevm->applied_hash, error));
        BOOST_CHECK(!chainman.CheckNEVMStartupConnect(*indexed_child, error));
    }

    bool genesis_notified{false};
    const boost::signals2::scoped_connection genesis_notification{
        uiInterface.NotifyBlockTip_connect(
            [&](SynchronizationState, const CBlockIndex* tip) {
                genesis_notified = tip != nullptr &&
                                   tip->GetBlockHash() == genesis_hash;
            })};
    // This is the caller that must release AppInitMain's genesis wait
    // before networking can obtain the still-missing pair header.
    m_node.notifications->m_shutdown_on_fatal_error = false;
    node::ImportBlocks(chainman, {}, nullptr, deterministicMNManager,
                       activeMasternodeManager, g_wallet_init_interface, m_node);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    BOOST_CHECK(genesis_notified);
    BOOST_CHECK(!chainman.m_blockman.LoadingBlocks());
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == genesis_hash);
        BOOST_CHECK(chainman.ActiveChainstate().CoinsTip().GetBestBlock() == genesis_hash);
    }
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    BOOST_CHECK(nevm->connected_blocks.empty());
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);

    BlockValidationState retry_state;
    BOOST_REQUIRE(chainman.RetryNEVMStartupPair(retry_state));
    BOOST_CHECK(retry_state.IsValid());
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveHeight()) == 0);
    BOOST_CHECK(chainman.HasPendingNEVMStartupPair());
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
