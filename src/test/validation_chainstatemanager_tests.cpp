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
#include <evo/providertx.h> // SYSCOIN: provider parent-state recovery.
#include <evo/specialtx_payload.h>
#include <evo/pq_payment_probation_db.h> // SYSCOIN: multi-chainstate probation GC.
#include <evo/pq_registry.h> // SYSCOIN: deep rollback registry roots.
#include <governance/governance.h> // SYSCOIN: tip-bound block fixture readiness.
#include <kernel/disconnected_transactions.h>
#include <kernel/context.h>
#include <llmq/pq_chainlock_persistence.h> // SYSCOIN: pre-import durable finality.
#include <llmq/pq_chainlock_schedule.h> // SYSCOIN: payment-audit preseal coverage.
#include <llmq/pq_payment_audit_staging_store.h> // SYSCOIN: durable audit reconstruction controls.
#include <llmq/quorums_chainlocks.h> // SYSCOIN: retained probation roots.
#include <llmq/quorums_init.h> // SYSCOIN: recreate pre-import finality handler.
#include <masternode/activemasternode.h>
#include <masternode/masternodemeta.h> // SYSCOIN: rebuild auxiliary fixture state.
#include <masternode/masternodesync.h> // SYSCOIN: replay before governance sync.
#include <netbase.h> // SYSCOIN: deterministic valid-MN fixture service.
#include <netfulfilledman.h> // SYSCOIN: rebuild auxiliary fixture state.
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/interface_ui.h> // SYSCOIN: startup's genesis notification.
#include <node/kernel_notifications.h>
#include <node/miner.h> // SYSCOIN: preserve NEVM template commitments.
#include <node/utxo_snapshot.h>
#include <pow.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <script/sign.h> // SYSCOIN: funded provider registration fixture.
#include <services/assetconsensus.h> // SYSCOIN: coins-recovery NEVM roots and mint markers.
#include <services/nevmconsensus.h> // SYSCOIN: rebuild auxiliary fixture databases.
#include <shutdown.h> // SYSCOIN: managed NEVM shutdown regression.
#include <spork.h> // SYSCOIN: rebuild auxiliary fixture state.
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
#include <cstddef> // SYSCOIN: serialized undo comparison.
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
                                     bool managed_exit = false,
                                     bool block_tree_db_in_memory = true)
        : TestChain100Setup{ChainType::REGTEST,
                            managed_exit
                                ? std::vector<const char*>{"-nevmstartheight=101",
                                                          "-gethcommandline=--exitwhensynced"}
                                : std::vector<const char*>{"-nevmstartheight=101"},
                            COINBASE_MATURITY,
                            coins_db_in_memory,
                            block_tree_db_in_memory} {}
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
    bool strict_connect_order{false};
    std::vector<AppliedPair> buffered_pairs;
    std::optional<AppliedPair> reported_pair_override;
    std::optional<AppliedPair> last_reported_pair;
    std::size_t flush_requests{0};
    bool status_available{true};
    std::size_t status_requests{0};
    std::string block_info_error;
    std::string connect_error;
    std::function<std::string(const uint256&, uint32_t)> connect_response;
    std::function<std::optional<NEVMBlockReject>(const uint256&)> connect_verdict;
    std::function<std::optional<NEVMBlockReject>()> flush_verdict;
    std::size_t payload_check_requests{0};
    std::vector<uint256> payload_checked_blocks;
    std::function<void(const CNEVMHeader&, const CBlock&, const uint256&,
                       bool&, std::string&, std::optional<NEVMBlockReject>*)>
        payload_check_response;
    std::string disconnect_error;
    bool strict_disconnect_order{false};
    std::vector<AppliedPair> applied_pairs;
    std::size_t block_info_queries{0};
    std::vector<uint256> connected_blocks;
    std::vector<uint256> disconnected_blocks;
    std::vector<std::string> command_trace;
    uint8_t template_serial{0};
    std::optional<uint256> template_block_hash;
    std::optional<NEVMTxRoot> template_roots;

    void NotifyGetNEVMBlock(CNEVMBlock& block, std::string& state) override
    {
        state.clear();
        template_serial = static_cast<uint8_t>(template_serial + 1U);
        block.nBlockHash.begin()[0] = template_serial;
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
        const CNEVMHeader& header, const CBlock& block, std::string& state,
        const uint256& hash, NEVMDataVec&, const uint32_t& height,
        bool, const uint256&,
        const CDeterministicMNListNEVMAddressDiff&,
        std::optional<NEVMBlockReject>* rejection = nullptr) override
    {
        state.clear();
        if (rejection) rejection->reset();
        if (hash.IsNull()) return;
        connected_blocks.push_back(hash);
        command_trace.push_back("connect:" + hash.ToString());
        if (!connect_error.empty()) {
            state = connect_error;
            return;
        }
        if (connect_verdict) {
            const auto verdict{connect_verdict(hash)};
            if (verdict) {
                if (rejection) *rejection = verdict;
                state = verdict->nevm_hash == header.nBlockHash &&
                        verdict->syscoin_hash == hash
                    ? (verdict->IsPayload() ? "nevm-connect-payload-invalid"
                                            : "nevm-connect-consensus-invalid")
                    : "nevm-connect-response-invalid-data";
                return;
            }
        }
        if (connect_response) {
            state = connect_response(hash, height);
            if (!state.empty()) return;
        }
        const AppliedPair incoming{height - 101 + 1, hash};
        if (strict_connect_order) {
            const auto last{buffered_pairs.empty()
                ? AppliedPair{applied_count, applied_hash}
                : buffered_pairs.back()};
            if (incoming.count == last.count && incoming.hash == last.hash) return;
            if (incoming.count != last.count + 1 ||
                (last.count > 0 && block.hashPrevBlock != last.hash)) {
                state = "nevm-connect-response-invalid-data";
                return;
            }
        }
        if (buffer_connects) {
            buffered_pair = incoming;
            if (strict_connect_order) buffered_pairs.push_back(incoming);
            return;
        }
        ApplyPair(incoming);
    }

    void NotifyNEVMPayloadCheck(
        const CNEVMHeader& header, const CBlock& block, const uint256& hash,
        bool& valid, std::string& error,
        std::optional<NEVMBlockReject>* rejection = nullptr) override
    {
        ++payload_check_requests;
        payload_checked_blocks.push_back(hash);
        command_trace.push_back("payloadcheck:" + hash.ToString());
        valid = false;
        error = "nevm-payload-check-unavailable";
        if (rejection) rejection->reset();
        if (payload_check_response) {
            payload_check_response(header, block, hash, valid, error, rejection);
        }
    }

    void ApplyPair(const AppliedPair& pair)
    {
        if (strict_disconnect_order) {
            BOOST_REQUIRE_EQUAL(pair.count, applied_count + 1);
            applied_pairs.push_back(pair);
        }
        applied_count = pair.count;
        applied_hash = pair.hash;
    }

    void NotifyNEVMComms(
        const std::string& command, bool& response,
        std::optional<NEVMBlockReject>* rejection = nullptr) override
    {
        if (rejection) rejection->reset();
        if (command == "status") {
            command_trace.push_back(command);
            ++status_requests;
            response = status_available;
            return;
        }
        if (command != "flush") return;
        command_trace.push_back(command);
        ++flush_requests;
        if (flush_verdict) {
            const auto verdict{flush_verdict()};
            if (verdict) {
                if (rejection) *rejection = verdict;
                response = false;
                buffered_pairs.clear();
                buffered_pair.reset();
                return;
            }
        }
        response = flush_available;
        if (!response) return;
        if (strict_connect_order) {
            for (const auto& pair : buffered_pairs) {
                BOOST_REQUIRE_EQUAL(pair.count, applied_count + 1);
                ApplyPair(pair);
            }
            buffered_pairs.clear();
            buffered_pair.reset();
            return;
        }
        if (buffered_pair) {
            ApplyPair(*buffered_pair);
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
        if (!state.empty() || !strict_disconnect_order) return;
        // A disconnect must remove the actual applied tip. This makes any
        // accidental external removal of an unapplied suffix fail closed.
        if (applied_pairs.empty() || applied_count != applied_pairs.size() ||
            applied_hash != hash || applied_pairs.back().hash != hash) {
            state = "nevm-disconnect-response-invalid-data";
            return;
        }
        applied_pairs.pop_back();
        applied_count = applied_pairs.size();
        applied_hash = applied_pairs.empty() ? uint256{} : applied_pairs.back().hash;
    }

    void NotifyGetNEVMBlockInfo(
        uint64_t& count, uint256& hash, std::string& state) override
    {
        ++block_info_queries;
        command_trace.push_back("blockinfo");
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
                                      bool managed_exit = false,
                                      bool block_tree_db_in_memory = true)
        : DeferredNEVMReplaySetup{coins_db_in_memory, managed_exit, block_tree_db_in_memory}
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
        const auto pair_queries{nevm->block_info_queries};
        const auto flushes{nevm->flush_requests};
        const bool recovery_expected{
            !engine_rejection && !managed_exit &&
            error != "nevm-connect-protocol-unsupported"};
        const std::size_t failed_attempts{recovery_expected ? 2U : 1U};
        const auto applied_hash{nevm->applied_hash};
        const auto applied_count{nevm->applied_count};
        // Ordinary send errors probe the engine. Managed shutdown must skip
        // that probe and exit even when the engine has already disappeared.
        nevm->status_available = !managed_exit;
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
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + failed_attempts);
        BOOST_CHECK_EQUAL(nevm->status_requests,
                          status_queries + (error == "nevm-connect-not-sent" && !managed_exit ? 1U : 0U));
        if (recovery_expected) {
            BOOST_CHECK_GT(nevm->block_info_queries, pair_queries);
            BOOST_CHECK_LE(nevm->block_info_queries, pair_queries + 2);
            BOOST_CHECK_GT(nevm->flush_requests, flushes);
            BOOST_CHECK_LE(nevm->flush_requests, flushes + 2);
        } else {
            BOOST_CHECK_EQUAL(nevm->block_info_queries, pair_queries);
            BOOST_CHECK_EQUAL(nevm->flush_requests, flushes);
        }
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
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + failed_attempts + 1);
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

struct LiveNEVMRecoverySetup : StartupNEVMRecoverySetup {
    std::vector<std::shared_ptr<const CBlock>> prefix;
    std::shared_ptr<const CBlock> candidate;
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* descendant_index{nullptr};
    CBlockIndex* original_tip{nullptr};
    uint256 durable_tip;
    std::size_t candidate_attempts{0};
    std::function<void()> before_prefix_mine;

    explicit LiveNEVMRecoverySetup(bool managed_exit = false)
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/true, managed_exit} {}

    void PrepareLostPrefix(std::size_t retained, std::size_t acknowledged = 3)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        struct ClearGovernanceReadiness {
            bool active;
            ~ClearGovernanceReadiness()
            {
                if (active && governance) governance->ObserveChainTip(nullptr);
            }
        } clear_governance_readiness{acknowledged > 3};
        const auto prepare_governance = [&] {
            if (!clear_governance_readiness.active) return;
            BOOST_REQUIRE(governance != nullptr);
            const CBlockIndex* parent{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
            BOOST_REQUIRE(parent != nullptr);
            BOOST_REQUIRE(governance_tests::PublishGovernanceReadyForTest(*governance, *parent));
        };
        nevm->strict_connect_order = true;
        nevm->buffer_connects = true;
        for (std::size_t i{0}; i < acknowledged; ++i) {
            prepare_governance();
            if (before_prefix_mine) before_prefix_mine();
            prefix.push_back(MineNEVMBlock());
        }
        BOOST_REQUIRE_EQUAL(nevm->applied_count, 0U);
        BOOST_REQUIRE_EQUAL(nevm->buffered_pairs.size(), prefix.size());
        prepare_governance();
        candidate = MakeNEVMBlock();
        {
            LOCK(::cs_main);
            original_tip = chainman.ActiveTip();
            durable_tip = chainstate.CoinsDB().GetBestBlock();
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                candidate, state, &candidate_index, /*fRequested=*/true,
                /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
                state.ToString());
        }
        CBlockHeader descendant{candidate->GetBlockHeader()};
        descendant.hashPrevBlock = candidate->GetHash();
        ++descendant.nTime;
        descendant.nNonce = 0;
        while (!CheckProofOfWork(descendant.GetHash(), descendant.nBits,
                                 chainman.GetConsensus())) ++descendant.nNonce;
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {descendant}, /*min_pow_checked=*/true, state), state.ToString());
        descendant_index = WITH_LOCK(::cs_main,
            return chainman.m_blockman.LookupBlockIndex(descendant.GetHash()));
        BOOST_REQUIRE(candidate_index != nullptr);
        BOOST_REQUIRE(descendant_index != nullptr);
        BOOST_REQUIRE_LE(retained, prefix.size());
        // Acknowledgements already advanced Core. Model only the engine's
        // retained applied prefix; no Core rollback or process crash is needed.
        nevm->applied_count = retained;
        nevm->applied_hash = retained == 0 ? uint256{} : prefix[retained - 1]->GetHash();
        nevm->buffered_pairs.clear();
        nevm->buffered_pair.reset();
        nevm->connected_blocks.clear();
        nevm->command_trace.clear();
    }

    void FailFirstCandidate(const std::string& first_error,
                            const std::string& retry_error = {})
    {
        nevm->connect_response = [this, first_error, retry_error](const uint256& hash, uint32_t) {
            if (hash != candidate->GetHash()) return std::string{};
            BOOST_REQUIRE_LE(++candidate_attempts, 2U);
            if (candidate_attempts == 1) return first_error;
            // Recovery must commit and verify the whole parent before retrying
            // the current candidate, even when replay itself is buffered.
            BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
            BOOST_CHECK(nevm->applied_hash == prefix.back()->GetHash());
            BOOST_CHECK(nevm->buffered_pairs.empty());
            nevm->buffer_connects = false;
            return retry_error;
        };
    }

    void CheckLocalState(bool connected, bool invalid = false)
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == (connected ? candidate_index : original_tip));
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == chainman.ActiveTip()->GetBlockHash());
        if (!connected) BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_tip);
        BOOST_CHECK_EQUAL(chainstate.CoinsTip().HaveCoin(
            COutPoint{candidate->vtx.front()->GetHash(), 0}), connected);
        BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK,
                          invalid ? BLOCK_FAILED_VALID : 0U);
        if (!connected) {
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), invalid ? 0U : 1U);
        }
        if (!invalid) BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
        for (const auto& block : prefix) {
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(COutPoint{block->vtx.front()->GetHash(), 0}));
            const auto* index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            CNEVMHeader header;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, *block, header));
            NEVMTxRoot roots;
            BOOST_CHECK(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots));
            BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
            BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
        }
        CNEVMHeader header;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, *candidate, header));
        NEVMTxRoot roots;
        BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots), connected);
        if (!connected) BOOST_CHECK(!pnevmtxrootsdb->Read(header.nBlockHash, roots));
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        BOOST_CHECK(fNEVMConnection);
    }

    void CheckLostPrefix(std::size_t retained, const std::string& error,
                         std::size_t acknowledged = 3)
    {
        PrepareLostPrefix(retained, acknowledged);
        FailFirstCandidate(error);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate),
                              state.ToString());
        BOOST_CHECK(state.IsValid());
        CheckLocalState(/*connected=*/true);
        BOOST_CHECK_EQUAL(candidate_attempts, 2U);
        BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size() + 1);
        BOOST_CHECK(nevm->applied_hash == candidate->GetHash());
        std::vector<std::string> expected{"connect:" + candidate->GetHash().ToString()};
        if (error == "nevm-connect-not-sent") expected.push_back("status");
        expected.insert(expected.end(), {"flush", "blockinfo"});
        for (std::size_t i{retained}; i < prefix.size(); ++i) {
            expected.push_back("connect:" + prefix[i]->GetHash().ToString());
            if ((i - retained + 1) % 64 == 0 || i + 1 == prefix.size()) {
                expected.insert(expected.end(), {"flush", "blockinfo"});
            }
        }
        expected.push_back("connect:" + candidate->GetHash().ToString());
        BOOST_CHECK(nevm->command_trace == expected);
    }
};

struct ManagedLiveNEVMRecoverySetup : LiveNEVMRecoverySetup {
    ManagedLiveNEVMRecoverySetup() : LiveNEVMRecoverySetup{/*managed_exit=*/true}
    {
        BOOST_REQUIRE(!ShutdownRequested());
    }
    ~ManagedLiveNEVMRecoverySetup() { AbortShutdown(); }
};

// SYSCOIN: Synthetic engine verdicts exercise reconciliation of locally valid
// fixture blocks through the real activation path and normal undo cleanup.
struct RejectedNEVMPrefixSetup : LiveNEVMRecoverySetup {
    enum class Boundary { INITIAL_CONNECT, DIRECT_REPLAY, INITIAL_FLUSH, BATCH_FLUSH };
    std::size_t verdict_deliveries{0};

    NEVMBlockReject VerdictFor(const CBlock& block)
    {
        CNEVMHeader header;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, block, header));
        return NEVMBlockReject{header.nBlockHash, block.GetHash()};
    }

    void PrepareRejection()
    {
        PrepareLostPrefix(1);
        nevm->strict_disconnect_order = true;
        nevm->applied_pairs = {{1, prefix.front()->GetHash()}};
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS),
                              state.ToString());
        durable_tip = chainstate.CoinsDB().GetBestBlock();
        BOOST_REQUIRE(durable_tip == original_tip->GetBlockHash());
        // Start with all acknowledged roots durable, including the suffix
        // whose authority a later engine verdict may revoke.
        for (const auto& block : prefix) {
            NEVMTxRoot roots;
            BOOST_REQUIRE(pnevmtxrootsdb->Read(VerdictFor(*block).nevm_hash, roots));
        }
    }

    void DeliverAt(Boundary boundary)
    {
        const auto verdict{VerdictFor(*prefix[1])};
        if (boundary != Boundary::INITIAL_CONNECT) {
            FailFirstCandidate("nevm-connect-response-invalid-data");
        }
        if (boundary == Boundary::INITIAL_CONNECT || boundary == Boundary::DIRECT_REPLAY) {
            const auto request{boundary == Boundary::INITIAL_CONNECT
                ? candidate->GetHash() : prefix[1]->GetHash()};
            nevm->connect_verdict = [this, request, verdict](const uint256& hash)
                -> std::optional<NEVMBlockReject> {
                if (hash != request) return std::nullopt;
                BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
                // DIRECT_REPLAY produces the exact requested-pair consensus
                // marker, preserving the replayed block's identity.
                return verdict;
            };
        } else {
            const std::size_t delivery_flush{
                boundary == Boundary::INITIAL_FLUSH ? 1U : 2U};
            nevm->flush_verdict = [this, delivery_flush, verdict]()
                -> std::optional<NEVMBlockReject> {
                if (nevm->flush_requests != delivery_flush) return std::nullopt;
                BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
                return verdict;
            };
        }
    }

    void CheckReconciled()
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        const auto surviving_hash{prefix.front()->GetHash()};
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == surviving_hash);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == surviving_hash);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == surviving_hash);
        BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
        BOOST_CHECK(nevm->applied_hash == surviving_hash);
        BOOST_REQUIRE(nevm->last_reported_pair.has_value());
        BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 1U);
        BOOST_CHECK(nevm->last_reported_pair->hash == surviving_hash);
        BOOST_REQUIRE_EQUAL(nevm->applied_pairs.size(), 1U);
        BOOST_CHECK(nevm->applied_pairs.front().hash == surviving_hash);
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        BOOST_CHECK(nevm->buffered_pairs.empty());
        BOOST_CHECK(!nevm->buffered_pair.has_value());
        BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
        BOOST_CHECK(fNEVMConnection);
        const auto check_persisted_status = [&](const CBlockIndex& index)
            EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            CDiskBlockIndex disk_index;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
                std::make_pair(uint8_t{'b'}, index.GetBlockHash()), disk_index));
            BOOST_CHECK_EQUAL(disk_index.nStatus & BLOCK_FAILED_MASK,
                              index.nStatus & BLOCK_FAILED_MASK);
        };
        for (std::size_t i{0}; i < prefix.size(); ++i) {
            const auto& block{prefix[i]};
            const bool retained{i == 0};
            auto* const index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            if (retained) {
                BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            } else if (i == 1) {
                BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
            } else {
                // Preserve the existing invalidation worker's bookkeeping
                // for previously accepted descendants.
                BOOST_CHECK(index->nStatus & BLOCK_FAILED_MASK);
            }
            check_persisted_status(*index);
            BOOST_CHECK_EQUAL(chainstate.CoinsTip().HaveCoin(
                COutPoint{block->vtx.front()->GetHash(), 0}), retained);
            CNEVMHeader header;
            BlockValidationState header_state;
            BOOST_REQUIRE(GetNEVMData(header_state, *block, header));
            NEVMTxRoot roots;
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots), retained);
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->Read(header.nBlockHash, roots), retained);
            if (retained) {
                BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
                BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
            } else {
                BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(index), 0U);
            }
        }
        // The pending request never acquired local state. Its branch depends
        // on the rejected ancestor, but it is not independently invalid.
        // Failed-child flags may be populated lazily by work selection; a
        // header-only descendant need not be visited or persisted here.
        BOOST_CHECK(!(candidate_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(descendant_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), 0U);
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
            COutPoint{candidate->vtx.front()->GetHash(), 0}));
        NEVMTxRoot candidate_roots;
        const auto candidate_nevm_hash{VerdictFor(*candidate).nevm_hash};
        BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(candidate_nevm_hash, candidate_roots));
        BOOST_CHECK(!pnevmtxrootsdb->Read(candidate_nevm_hash, candidate_roots));

        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == surviving_hash);
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
    }

    void CheckBoundary(Boundary boundary)
    {
        PrepareRejection();
        DeliverAt(boundary);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate),
                              state.ToString());
        BOOST_CHECK(state.IsValid());
        CheckReconciled();
        std::vector<uint256> expected{candidate->GetHash()};
        if (boundary == Boundary::DIRECT_REPLAY || boundary == Boundary::BATCH_FLUSH) {
            expected.push_back(prefix[1]->GetHash());
        }
        if (boundary == Boundary::BATCH_FLUSH) expected.push_back(prefix[2]->GetHash());
        BOOST_CHECK(nevm->connected_blocks == expected);
    }
};

// SYSCOIN: These payloads remain opaque, locally valid mock-engine fixtures.
// Only synthetic notifier verdicts select the recovery path.
const auto NEVM_PAYLOAD_TEST_MARKER{
    std::make_pair(uint8_t{'F'}, std::string{"nevm_payload_repair_v1"})};

NEVMBlockReject PayloadVerdictFor(const CBlock& block)
{
    CNEVMHeader header;
    BlockValidationState state;
    BOOST_REQUIRE(GetNEVMData(state, block, header));
    return {header.nBlockHash, block.GetHash(), NEVMPayloadFingerprint(
        header.nBlockHash, header.nTxRoot, header.nReceiptRoot,
        block.GetHash(), block.vchNEVMBlockData)};
}

struct NEVMPayloadRepairSetup : RejectedNEVMPrefixSetup {
    const std::vector<uint8_t> replacement_payload{0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64};
    NEVMBlockReject payload_verdict;
    CBlockIndex* repaired_index{nullptr};
    std::optional<CDiskBlockIndex> saved_index;
    unsigned int saved_chain_tx{0};
    int32_t saved_sequence_id{0};
    std::vector<std::byte> saved_undo;

    void PreparePayloadFixture()
    {
        PrepareRejection();
        payload_verdict = PayloadVerdictFor(*prefix[1]);
        LOCK(::cs_main);
        repaired_index = m_node.chainman->m_blockman.LookupBlockIndex(prefix[1]->GetHash());
        BOOST_REQUIRE(repaired_index != nullptr);
        saved_index.emplace(repaired_index);
        saved_chain_tx = repaired_index->nChainTx;
        saved_sequence_id = repaired_index->nSequenceId;
        CBlockUndo undo;
        BOOST_REQUIRE(m_node.chainman->m_blockman.UndoReadFromDisk(undo, *repaired_index));
        CDataStream stream{SER_DISK, CLIENT_VERSION};
        stream << undo;
        saved_undo.assign(stream.begin(), stream.end());
    }

    void DeliverPayloadVerdict(bool correct_fingerprint = true)
    {
        FailFirstCandidate("nevm-connect-response-invalid-data");
        auto verdict{payload_verdict};
        if (!correct_fingerprint) verdict.payload_hash->begin()[0] ^= 1;
        nevm->connect_verdict = [this, verdict](const uint256& hash)
            -> std::optional<NEVMBlockReject> {
            if (hash != prefix[1]->GetHash()) return std::nullopt;
            ++verdict_deliveries;
            return verdict;
        };
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), correct_fingerprint
            ? "nevm-payload-repair-pending" : "nevm-payload-repair-fingerprint-mismatch");
        CheckLocalState(/*connected=*/false);
        BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    }

    NEVMPayloadRepairRequest Request()
    {
        LOCK(::cs_main);
        const auto request{m_node.chainman->GetNEVMPayloadRepairRequest()};
        BOOST_REQUIRE(request.has_value());
        BOOST_CHECK(request->rejection == payload_verdict);
        NEVMBlockReject persisted;
        BOOST_REQUIRE(m_node.chainman->m_blockman.m_block_tree_db->Read(
            NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == payload_verdict);
        return *request;
    }

    void CheckStoredPayload(Span<const uint8_t> payload, bool positions_unchanged)
    {
        LOCK(::cs_main);
        auto& blockman{m_node.chainman->m_blockman};
        CBlock stored;
        BOOST_REQUIRE(blockman.ReadBlockFromDisk(stored, *repaired_index, false));
        BOOST_CHECK_EQUAL_COLLECTIONS(stored.vchNEVMBlockData.begin(), stored.vchNEVMBlockData.end(),
                                      payload.begin(), payload.end());
        stored.vchNEVMBlockData = prefix[1]->vchNEVMBlockData;
        CDataStream old_wrapper{SER_DISK, CLIENT_VERSION}, new_wrapper{SER_DISK, CLIENT_VERSION};
        old_wrapper << *prefix[1];
        new_wrapper << stored;
        BOOST_CHECK_EQUAL_COLLECTIONS(old_wrapper.begin(), old_wrapper.end(),
                                      new_wrapper.begin(), new_wrapper.end());
        BOOST_REQUIRE(saved_index.has_value());
        if (positions_unchanged) {
            BOOST_CHECK(repaired_index->GetBlockPos() == saved_index->GetBlockPos());
            BOOST_CHECK(repaired_index->GetUndoPos() == saved_index->GetUndoPos());
        }
        CDiskBlockIndex current{repaired_index};
        current.nFile = saved_index->nFile;
        current.nDataPos = saved_index->nDataPos;
        current.nUndoPos = saved_index->nUndoPos;
        CDataStream old_index{SER_DISK, CLIENT_VERSION}, new_index{SER_DISK, CLIENT_VERSION};
        old_index << *saved_index;
        new_index << current;
        BOOST_CHECK_EQUAL_COLLECTIONS(old_index.begin(), old_index.end(),
                                      new_index.begin(), new_index.end());
        BOOST_CHECK_EQUAL(repaired_index->nChainTx, saved_chain_tx);
        BOOST_CHECK_EQUAL(repaired_index->nSequenceId, saved_sequence_id);
        CBlockUndo undo;
        BOOST_REQUIRE(blockman.UndoReadFromDisk(undo, *repaired_index));
        CDataStream undo_bytes{SER_DISK, CLIENT_VERSION};
        undo_bytes << undo;
        BOOST_CHECK_EQUAL_COLLECTIONS(undo_bytes.begin(), undo_bytes.end(),
                                      saved_undo.begin(), saved_undo.end());
    }

    void ConfigurePayloadCheck()
    {
        nevm->payload_check_response = [this](
            const CNEVMHeader& header, const CBlock& block, const uint256& hash,
            bool& valid, std::string& error, std::optional<NEVMBlockReject>* rejection) {
            BOOST_CHECK(hash == payload_verdict.syscoin_hash);
            BOOST_CHECK(block.GetHash() == hash);
            BOOST_CHECK(header.nBlockHash == payload_verdict.nevm_hash);
            CNEVMHeader original_header;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, *prefix[1], original_header));
            BOOST_CHECK(header.nTxRoot == original_header.nTxRoot);
            BOOST_CHECK(header.nReceiptRoot == original_header.nReceiptRoot);
            valid = block.vchNEVMBlockData == replacement_payload;
            error = valid ? std::string{} : "fixture-payload-rejected";
            if (!valid && rejection) *rejection = PayloadVerdictFor(block);
        };
    }

    void CompleteRepair()
    {
        nevm->connect_verdict = {};
        nevm->buffer_connects = false;
        std::string error;
        BOOST_REQUIRE_MESSAGE(m_node.chainman->MaybeRecoverNEVMPayload(error), error);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(!m_node.chainman->HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!WITH_LOCK(::cs_main,
            return m_node.chainman->m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER)));
        CheckLocalState(/*connected=*/true);
        BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size() + 1);
        BOOST_CHECK(nevm->applied_hash == candidate->GetHash());
    }
};

struct NEVMPayloadForkSetup : NEVMPayloadRepairSetup {
    const bool previous_shutdown_on_fatal_error{
        m_node.notifications->m_shutdown_on_fatal_error};
    std::vector<std::shared_ptr<const CBlock>> fork;
    CBlockIndex* fork_tip{nullptr};

    NEVMPayloadForkSetup()
    {
        // A regression must report a failed check without stopping the runner.
        m_node.notifications->m_shutdown_on_fatal_error = false;
    }

    ~NEVMPayloadForkSetup()
    {
        m_node.notifications->m_shutdown_on_fatal_error = previous_shutdown_on_fatal_error;
        m_node.exit_status.store(EXIT_SUCCESS);
    }

    void AppendForkTemplate()
    {
        auto& chainman{*m_node.chainman};
        CBlock block{*MakeNEVMBlock()};
        BOOST_REQUIRE_EQUAL(block.vtx.size(), 1U);
        BOOST_REQUIRE_LT(WITH_LOCK(::cs_main, return chainman.ActiveHeight()) + 1,
                         chainman.GetConsensus().DIP0003Height);
        // These unused, height-matched templates contain only a coinbase and
        // unique opaque mock NEVM data. Reparenting preserves their local
        // validity, as in the competing startup-pair fixtures.
        if (!fork.empty()) block.hashPrevBlock = fork.back()->GetHash();
        block.fChecked = false;
        block.nNonce = 0;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) {
            ++block.nNonce;
        }
        fork.push_back(std::make_shared<const CBlock>(std::move(block)));
    }

    void PrepareFork(bool below_applied)
    {
        before_prefix_mine = [this, below_applied] {
            if (below_applied || !prefix.empty()) AppendForkTemplate();
        };
        PreparePayloadFixture();
        before_prefix_mine = {};
        AppendForkTemplate();
        DeliverPayloadVerdict();
        nevm->buffer_connects = false;
        auto& chainman{*m_node.chainman};
        LOCK(::cs_main);
        for (const auto& block : fork) {
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                block, state, &fork_tip, true, nullptr, nullptr, true), state.ToString());
            BOOST_REQUIRE(fork_tip != nullptr);
        }
        BOOST_REQUIRE(fork_tip->nChainWork > chainman.ActiveTip()->nChainWork);
        BOOST_REQUIRE_EQUAL(chainman.ActiveChain().FindFork(fork_tip)->nHeight,
                            below_applied ? 100 : 101);
        BOOST_REQUIRE_EQUAL(nevm->applied_count, 1U);
        BOOST_REQUIRE(nevm->applied_hash == prefix.front()->GetHash());
        BOOST_REQUIRE(nevm->strict_disconnect_order);
    }

    void CheckForkSelected(bool below_applied)
    {
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        const auto connects{nevm->connected_blocks.size()};
        const auto queries{nevm->block_info_queries};
        const auto flushes{nevm->flush_requests};
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainstate.PreciousBlock(state, fork_tip), state.ToString());
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK_EQUAL(nevm->block_info_queries, queries + 1);
        BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
        BOOST_CHECK(nevm->disconnected_blocks == (below_applied
            ? std::vector<uint256>{prefix.front()->GetHash()} : std::vector<uint256>{}));
        std::vector<uint256> expected_connects;
        for (const auto& block : fork) expected_connects.push_back(block->GetHash());
        BOOST_CHECK(std::vector<uint256>(nevm->connected_blocks.begin() + connects,
                                        nevm->connected_blocks.end()) == expected_connects);
        BOOST_CHECK_EQUAL(nevm->applied_count, 4U);
        BOOST_CHECK_EQUAL(nevm->applied_pairs.size(), 4U);
        BOOST_CHECK(nevm->applied_hash == fork.back()->GetHash());
        std::string error;
        BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
        BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
        CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
        LOCK(::cs_main);
        BlockValidationState flush_state;
        BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(flush_state, FlushStateMode::ALWAYS),
                              flush_state.ToString());
        BOOST_CHECK(chainman.ActiveTip() == fork_tip);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == fork.back()->GetHash());
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == fork.back()->GetHash());
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == fork.back()->GetHash());
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER));
        const auto check_block = [&](const CBlock& block, bool active)
            EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            const auto* index{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            const COutPoint coin{block.vtx.front()->GetHash(), 0};
            BOOST_CHECK_EQUAL(chainstate.CoinsTip().HaveCoin(coin), active);
            BOOST_CHECK_EQUAL(chainstate.CoinsDB().HaveCoin(coin), active);
            CNEVMHeader header;
            BlockValidationState header_state;
            BOOST_REQUIRE(GetNEVMData(header_state, block, header));
            NEVMTxRoot roots;
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots), active);
            BOOST_CHECK_EQUAL(pnevmtxrootsdb->Read(header.nBlockHash, roots), active);
            if (active) {
                BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
                BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
            }
        };
        for (std::size_t i{0}; i < prefix.size(); ++i) {
            check_block(*prefix[i], !below_applied && i == 0);
        }
        for (const auto& block : fork) check_block(*block, true);
        check_block(*candidate, false);
        BOOST_CHECK_EQUAL(descendant_index->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK(fNEVMConnection);
    }

    void CheckExplicitUnwind(bool conflict)
    {
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        const auto connects{nevm->connected_blocks};
        const auto queries{nevm->block_info_queries};
        const auto flushes{nevm->flush_requests};
        CBlockIndex* applied{WITH_LOCK(::cs_main,
            return chainman.m_blockman.LookupBlockIndex(prefix.front()->GetHash()))};
        BOOST_REQUIRE(applied != nullptr);
        BlockValidationState state;
        if (conflict) {
            LOCK(::cs_main);
            BOOST_REQUIRE_MESSAGE(chainstate.MarkConflictingBlock(state, applied), state.ToString());
        } else {
            BOOST_REQUIRE_MESSAGE(chainstate.InvalidateBlock(state, applied, /*bReverify=*/true),
                                  state.ToString());
        }
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK_EQUAL(nevm->block_info_queries, queries + 1);
        BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
        // Both public operations cross P after locally removing unapplied B/A.
        // The actual applied P must still receive its ordinary engine undo.
        BOOST_CHECK(nevm->disconnected_blocks == std::vector<uint256>{prefix.front()->GetHash()});
        BOOST_CHECK(nevm->connected_blocks == connects);
        BOOST_CHECK_EQUAL(nevm->applied_count, 0U);
        BOOST_CHECK(nevm->applied_hash.IsNull());
        BOOST_CHECK(nevm->applied_pairs.empty());
        BOOST_CHECK(nevm->buffered_pairs.empty());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
        LOCK(::cs_main);
        BlockValidationState flush_state;
        BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(flush_state, FlushStateMode::ALWAYS),
                              flush_state.ToString());
        const auto parent{prefix.front()->hashPrevBlock};
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == parent);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent);
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == parent);
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        for (const auto& block : prefix) {
            const auto* index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            if (conflict) {
                BOOST_CHECK(index->nStatus & BLOCK_CONFLICT_CHAINLOCK);
                BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            } else {
                BOOST_CHECK(index->nStatus & BLOCK_FAILED_MASK);
            }
            CDiskBlockIndex disk_index;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
                std::make_pair(uint8_t{'b'}, block->GetHash()), disk_index));
            BOOST_CHECK_EQUAL(disk_index.nStatus, index->nStatus);
            const COutPoint coin{block->vtx.front()->GetHash(), 0};
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(coin));
            BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(coin));
            NEVMTxRoot roots;
            const auto nevm_hash{VerdictFor(*block).nevm_hash};
            BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(nevm_hash, roots));
            BOOST_CHECK(!pnevmtxrootsdb->Read(nevm_hash, roots));
        }
        BOOST_CHECK_EQUAL(fork_tip->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(fork_tip), 1U);
        BOOST_CHECK(!(candidate_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(descendant_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(fNEVMConnection);
    }

    void CheckRefusedFork(const std::string& reason, bool queried = true)
    {
        const auto request{Request()};
        const auto connects{nevm->connected_blocks};
        const auto queries{nevm->block_info_queries};
        const auto flushes{nevm->flush_requests};
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().PreciousBlock(state, fork_tip));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
        BOOST_CHECK_EQUAL(nevm->block_info_queries, queries + (queried ? 1U : 0U));
        BOOST_CHECK(nevm->connected_blocks == connects);
        BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
        BOOST_REQUIRE_EQUAL(nevm->applied_pairs.size(), 1U);
        BOOST_CHECK(nevm->applied_hash == prefix.front()->GetHash());
        BOOST_CHECK(Request() == request);
        CheckLocalState(/*connected=*/false);
        CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
        LOCK(::cs_main);
        for (const auto& block : prefix) {
            NEVMTxRoot roots;
            BOOST_CHECK(pnevmtxrootsdb->Read(VerdictFor(*block).nevm_hash, roots));
        }
        for (const auto& block : fork) {
            const auto* index{m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK(!m_node.chainman->ActiveChainstate().CoinsTip().HaveCoin(
                COutPoint{block->vtx.front()->GetHash(), 0}));
        }
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == original_tip->GetBlockHash());
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    }
};

struct PersistentNEVMPayloadRepairSetup : StartupNEVMRecoverySetup {
    PersistentNEVMPayloadRepairSetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/true,
                                    /*managed_exit=*/false,
                                    /*block_tree_db_in_memory=*/false} {}

    void CheckReopenedMarker(bool replacement_published)
    {
        const auto first{MineNEVMBlock()};
        const auto second{MineNEVMBlock()};
        auto& chainman{*m_node.chainman};
        const auto verdict{PayloadVerdictFor(*second)};
        const std::vector<uint8_t> replacement{0x51, 0x52};
        nevm->payload_check_response = [&](
            const CNEVMHeader&, const CBlock& block, const uint256& hash,
            bool& valid, std::string& error, std::optional<NEVMBlockReject>* rejection) {
            BOOST_CHECK(hash == second->GetHash());
            valid = block.vchNEVMBlockData == replacement;
            error = valid ? std::string{} : "fixture-payload-rejected";
            if (!valid && rejection) *rejection = verdict;
        };
        std::string error;
        BOOST_REQUIRE_MESSAGE(chainman.DiscoverNEVMPayloadRepair(1, first->GetHash(), error), error);
        const auto request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
        BOOST_REQUIRE(request.has_value());
        if (replacement_published) {
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.ProcessNEVMPayloadRepair(*request, replacement, state),
                                  state.ToString());
        }
        SyncWithValidationInterfaceQueue();
        ChainstateManager restarted{m_node.kernel->interrupt, chainman.m_options,
            {.chainparams = chainman.GetParams(),
             .blocks_dir = m_args.GetBlocksDirPath(),
             .notifications = *m_node.notifications}};
        LOCK(::cs_main);
        const auto db_path{chainman.m_blockman.m_block_tree_db->StoragePath()};
        BOOST_REQUIRE(db_path.has_value());
        chainman.m_blockman.m_block_tree_db.reset();
        restarted.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
            .path = *db_path, .cache_bytes = 1U << 20});
        struct RestoreIndexDB {
            BlockManager& original;
            BlockManager& reopened;
            ~RestoreIndexDB()
            {
                original.m_block_tree_db = std::move(reopened.m_block_tree_db);
            }
        } restore{chainman.m_blockman, restarted.m_blockman};
        BOOST_REQUIRE(restarted.m_blockman.LoadBlockIndexDB(std::nullopt));
        const auto* index{restarted.m_blockman.LookupBlockIndex(second->GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK(index != chainman.m_blockman.LookupBlockIndex(second->GetHash()));
        BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
        CBlock stored;
        BOOST_REQUIRE(restarted.m_blockman.ReadBlockFromDisk(stored, *index, false));
        BOOST_CHECK(stored.vchNEVMBlockData ==
                    (replacement_published ? replacement : second->vchNEVMBlockData));
        BOOST_CHECK(!restarted.HasPendingNEVMPayloadRepair());
        const auto checks{nevm->payload_check_requests};
        BOOST_REQUIRE_MESSAGE(restarted.InitializeNEVMPayloadRepair(error), error);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(restarted.HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!restarted.GetNEVMPayloadRepairRequest());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, checks);
        NEVMBlockReject persisted;
        BOOST_REQUIRE(restarted.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == verdict);
    }
};

// SYSCOIN BEGIN: Pure validation may prove an immutable committed-root error.
struct ImmutableNEVMPayloadRepairSetup : StartupNEVMRecoverySetup {
    std::shared_ptr<const CBlock> parent;
    std::shared_ptr<const CBlock> candidate;
    CBlockIndex* parent_index{nullptr};
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* descendant_index{nullptr};
    const std::vector<uint8_t> proof_payload{0x49, 0x4d, 0x4d};
    NEVMBlockReject payload_verdict;
    NEVMBlockReject permanent_verdict;
    FlatFilePos original_pos;
    FlatFilePos original_undo;
    std::optional<NEVMBlockReject> pure_override;
    bool pure_unavailable{false};

    ImmutableNEVMPayloadRepairSetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/false,
                                    /*managed_exit=*/false,
                                    /*block_tree_db_in_memory=*/false} {}

    void Prepare(bool stored_proof, bool active_candidate = false)
    {
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        if (active_candidate) {
            CBlock block;
            LOCK(::cs_main);
            BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(block, *chainman.ActiveTip(), false));
            parent = std::make_shared<const CBlock>(std::move(block));
        } else {
            parent = MineNEVMBlock();
        }
        CBlock block{*MakeNEVMBlock()};
        if (stored_proof) block.vchNEVMBlockData = proof_payload;
        candidate = std::make_shared<const CBlock>(std::move(block));
        payload_verdict = PayloadVerdictFor(*candidate);
        permanent_verdict = NEVMBlockReject{payload_verdict.nevm_hash, candidate->GetHash()};
        {
            LOCK(::cs_main);
            parent_index = chainman.ActiveTip();
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                candidate, state, &candidate_index, true, nullptr, nullptr, true), state.ToString());
            BOOST_REQUIRE(candidate_index != nullptr);
            original_pos = candidate_index->GetBlockPos();
            original_undo = candidate_index->GetUndoPos();
        }
        if (active_candidate) {
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state, candidate), state.ToString());
            BOOST_REQUIRE(WITH_LOCK(::cs_main, return chainman.ActiveTip()) == candidate_index);
            // Model a fresh engine with a Core suffix already committed locally.
            nevm->applied_count = 0;
            nevm->applied_hash.SetNull();
        }
        CBlockHeader descendant{candidate->GetBlockHeader()};
        descendant.hashPrevBlock = candidate->GetHash();
        ++descendant.nTime;
        descendant.nNonce = 0;
        while (!CheckProofOfWork(descendant.GetHash(), descendant.nBits,
                                 chainman.GetConsensus())) ++descendant.nNonce;
        BlockValidationState descendant_state;
        BOOST_REQUIRE_MESSAGE(chainman.ProcessNewBlockHeaders(
            {descendant}, true, descendant_state), descendant_state.ToString());
        {
            LOCK(::cs_main);
            descendant_index = chainman.m_blockman.LookupBlockIndex(descendant.GetHash());
            BOOST_REQUIRE(descendant_index != nullptr);
            original_undo = candidate_index->GetUndoPos();
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS), state.ToString());
        }
        // The engine alone decodes opaque payload bytes. Crucially, normal
        // connection inspects the stored representation, so merely entering
        // REPLAY without durably replacing a wrong header cannot pass.
        nevm->connect_verdict = [this](const uint256& hash) -> std::optional<NEVMBlockReject> {
            if (hash != candidate->GetHash()) return std::nullopt;
            CBlock stored;
            LOCK(::cs_main);
            BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(stored, *candidate_index, false));
            return stored.vchNEVMBlockData == proof_payload
                ? permanent_verdict : PayloadVerdictFor(stored);
        };
        nevm->payload_check_response = [this](
            const CNEVMHeader& header, const CBlock& checked, const uint256& hash,
            bool& valid, std::string& error, std::optional<NEVMBlockReject>* rejection) {
            BOOST_CHECK(hash == candidate->GetHash());
            BOOST_CHECK(header.nBlockHash == permanent_verdict.nevm_hash);
            valid = false;
            error = pure_unavailable ? "fixture-check-unavailable" : "fixture-committed-roots-invalid";
            if (!pure_unavailable && rejection) {
                *rejection = pure_override.value_or(checked.vchNEVMBlockData == proof_payload
                    ? permanent_verdict : PayloadVerdictFor(checked));
            }
        };
        nevm->connected_blocks.clear();
        nevm->disconnected_blocks.clear();
    }

    void CheckStored(bool replaced)
    {
        LOCK(::cs_main);
        CBlock stored;
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(stored, *candidate_index, false));
        BOOST_CHECK(stored.GetHash() == candidate->GetHash());
        BOOST_REQUIRE_EQUAL(stored.vtx.size(), candidate->vtx.size());
        for (std::size_t i{0}; i < stored.vtx.size(); ++i) {
            BOOST_CHECK(stored.vtx[i]->GetHash() == candidate->vtx[i]->GetHash());
        }
        BOOST_CHECK(stored.vchNEVMBlockData == (replaced ? proof_payload : candidate->vchNEVMBlockData));
        BOOST_CHECK_EQUAL(candidate_index->GetBlockPos() == original_pos, !replaced);
        BOOST_CHECK(candidate_index->GetUndoPos() == original_undo);
    }

    void CheckParent(bool invalid)
    {
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == parent_index);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetHash());
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent->GetHash());
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        const COutPoint parent_coin{parent->vtx.front()->GetHash(), 0};
        const COutPoint candidate_coin{candidate->vtx.front()->GetHash(), 0};
        BOOST_CHECK(chainstate.CoinsTip().HaveCoin(parent_coin));
        BOOST_CHECK(chainstate.CoinsDB().HaveCoin(parent_coin));
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(candidate_coin));
        BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(candidate_coin));
        BOOST_CHECK_EQUAL(parent_index->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, invalid ? BLOCK_FAILED_VALID : 0U);
        BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_CONFLICT_CHAINLOCK, 0U);
        BOOST_CHECK(!(descendant_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(candidate_index), invalid ? 1U : 0U);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(parent_index), 0U);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), invalid ? 0U : 1U);
        NEVMTxRoot roots;
        BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(permanent_verdict.nevm_hash, roots));
        BOOST_CHECK(!pnevmtxrootsdb->Read(permanent_verdict.nevm_hash, roots));
        if (parent->IsNEVM()) {
            CNEVMHeader header;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, *parent, header));
            BOOST_REQUIRE(pnevmtxrootsdb->Read(header.nBlockHash, roots));
            BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
            BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
        }
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == parent->GetHash());
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        BOOST_CHECK_EQUAL(nevm->applied_count, parent->IsNEVM() ? 1U : 0U);
        BOOST_CHECK(nevm->applied_hash == (parent->IsNEVM() ? parent->GetHash() : uint256{}));
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        BOOST_CHECK(fNEVMConnection);
    }

    void RecoverAndCheckInvalid(bool replaced)
    {
        auto& chainman{*m_node.chainman};
        std::string error;
        BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
        // An active rejected suffix leaves an obsolete marker for the next
        // normal recovery pass; clearing it must not wait for a retry timer.
        BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
        BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()));
        CheckParent(/*invalid=*/true);
        CheckStored(replaced);
        BOOST_CHECK(nevm->connected_blocks == std::vector<uint256>{candidate->GetHash()});
        BlockValidationState retry_state;
        BOOST_REQUIRE_MESSAGE(chainman.ActiveChainstate().ActivateBestChain(retry_state, candidate), retry_state.ToString());
        BOOST_CHECK(nevm->connected_blocks == std::vector<uint256>{candidate->GetHash()});
        LOCK(::cs_main);
        BlockValidationState flush_state;
        BOOST_REQUIRE_MESSAGE(chainman.ActiveChainstate().FlushStateToDisk(
            flush_state, FlushStateMode::ALWAYS), flush_state.ToString());
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER));
        CDiskBlockIndex disk_candidate;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
            std::make_pair(uint8_t{'b'}, candidate->GetHash()), disk_candidate));
        BOOST_CHECK_EQUAL(disk_candidate.nStatus & BLOCK_FAILED_MASK, BLOCK_FAILED_VALID);
    }
};
// SYSCOIN END: Pure validation may prove an immutable committed-root error.

// SYSCOIN BEGIN: Use disk coins and index state for failed repair retargeting.
struct FailedNEVMPayloadRetargetSetup : StartupNEVMRecoverySetup {
    const bool previous_shutdown_on_fatal_error{m_node.notifications->m_shutdown_on_fatal_error};

    FailedNEVMPayloadRetargetSetup()
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/false,
                                    /*managed_exit=*/false,
                                    /*block_tree_db_in_memory=*/false}
    {
        m_node.notifications->m_shutdown_on_fatal_error = false;
    }

    ~FailedNEVMPayloadRetargetSetup()
    {
        WITH_LOCK(::cs_main,
            m_node.chainman->ActiveChainstate().CoinsDB().SetWriteBatchCallbackForTesting({}));
        m_node.notifications->m_shutdown_on_fatal_error = previous_shutdown_on_fatal_error;
        m_node.exit_status.store(EXIT_SUCCESS);
    }
};
// SYSCOIN END: Use disk coins and index state for failed repair retargeting.

struct NEVMPayloadReindexSetup : StartupNEVMRecoverySetup {
    enum class ImmutableProof { NONE, REPLACEMENT, ORIGINAL };

    void CheckReindexDuplicate(bool queued, bool changed = true,
                               ImmutableProof proof = ImmutableProof::NONE)
    {
        const auto parent{MineNEVMBlock()};
        const auto original{MakeNEVMBlock()};
        CBlock replacement{*original};
        if (changed) replacement.vchNEVMBlockData = {0x4f, 0x4b};
        const auto verdict{PayloadVerdictFor(*original)};
        const NEVMBlockReject permanent{verdict.nevm_hash, verdict.syscoin_hash};
        auto& chainman{*m_node.chainman};
        struct RestoreFatalError {
            node::KernelNotifications& notifications;
            std::atomic<int>& exit_status;
            const bool previous{notifications.m_shutdown_on_fatal_error};
            ~RestoreFatalError()
            {
                notifications.m_shutdown_on_fatal_error = previous;
                exit_status.store(EXIT_SUCCESS);
            }
        } restore_fatal{*m_node.notifications, m_node.exit_status};
        m_node.notifications->m_shutdown_on_fatal_error = false;
        FlatFilePos original_pos, replacement_pos;
        const auto write_record = [](CAutoFile& file, int number, const CBlock& block) {
            const auto size{static_cast<unsigned int>(GetSerializeSize(block, CLIENT_VERSION, SER_DISK))};
            file << Params().MessageStart() << size;
            const auto offset{ftell(file.Get())};
            BOOST_REQUIRE_GE(offset, 0);
            file << block;
            return FlatFilePos{number, static_cast<unsigned int>(offset)};
        };
        // LoadExternalBlockFile numbers offsets from the start of its stream.
        // Isolate the records in complete files and always open them at zero.
        const int record_file{1};
        const int trigger_file{2};
        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.m_blockman.LookupBlockIndex(original->GetHash()));
            BOOST_REQUIRE(!fs::exists(chainman.m_blockman.GetBlockPosFilename({record_file, 0})));
            BOOST_REQUIRE(!fs::exists(chainman.m_blockman.GetBlockPosFilename({trigger_file, 0})));
            CAutoFile records{chainman.m_blockman.OpenBlockFile({record_file, 0})};
            BOOST_REQUIRE(!records.IsNull());
            original_pos = write_record(records, record_file, *original);
            replacement_pos = write_record(records, record_file, replacement);
            if (queued) {
                CAutoFile trigger{chainman.m_blockman.OpenBlockFile({trigger_file, 0})};
                BOOST_REQUIRE(!trigger.IsNull());
                write_record(trigger, trigger_file, *parent);
            }
        }
        nevm->payload_check_response = [&](
            const CNEVMHeader& header, const CBlock& block, const uint256& hash,
            bool& valid, std::string& error, std::optional<NEVMBlockReject>* rejection) {
            BOOST_CHECK(hash == original->GetHash());
            BOOST_CHECK(header.nBlockHash == verdict.nevm_hash);
            const bool is_proof{proof == ImmutableProof::ORIGINAL ||
                (proof == ImmutableProof::REPLACEMENT &&
                 block.vchNEVMBlockData == replacement.vchNEVMBlockData)};
            valid = !is_proof && block.vchNEVMBlockData == replacement.vchNEVMBlockData;
            error = valid ? std::string{} : "fixture-payload-rejected";
            if (!valid && rejection) *rejection = is_proof ? permanent : verdict;
        };
        std::multimap<uint256, FlatFilePos> unknown_parent;
        if (queued) {
            // Retained offsets model children encountered in an earlier file
            // before their parent. Both same-hash records must be reconsidered.
            unknown_parent.emplace(parent->GetHash(), original_pos);
            unknown_parent.emplace(parent->GetHash(), replacement_pos);
        }
        struct ReindexGuard {
            const bool previous{node::fReindex.load()};
            ~ReindexGuard() { node::fReindex = previous; }
        } reindex_guard;
        node::fReindex = true;
        FlatFilePos scan_pos{queued ? trigger_file : record_file, 0};
        CAutoFile file{chainman.m_blockman.OpenBlockFile(scan_pos, true)};
        BOOST_REQUIRE(!file.IsNull());
        chainman.LoadExternalBlockFile(file, &scan_pos, &unknown_parent);
        BOOST_REQUIRE_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
        BOOST_CHECK(unknown_parent.empty());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests,
                          !changed ? 0U : proof == ImmutableProof::ORIGINAL ? 1U : 2U);
        const bool adopted{changed && proof != ImmutableProof::ORIGINAL};
        CBlockIndex* index{nullptr};
        {
            LOCK(::cs_main);
            index = chainman.m_blockman.LookupBlockIndex(original->GetHash());
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK(index->GetBlockPos() == (adopted ? replacement_pos : original_pos));
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK(!(index->nStatus & BLOCK_HAVE_UNDO));
            CBlock stored;
            BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(stored, *index, false));
            BOOST_CHECK(stored.GetHash() == original->GetHash());
            BOOST_CHECK(stored.vchNEVMBlockData ==
                        (adopted ? replacement.vchNEVMBlockData : original->vchNEVMBlockData));
            BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == parent->GetHash());
        }
        if (proof == ImmutableProof::NONE) return;
        // Reindex only preserves the representation. Once import ends, the
        // ordinary connector must independently reject the committed pair.
        node::fReindex = reindex_guard.previous;
        nevm->connect_verdict = [&, index](const uint256& hash) -> std::optional<NEVMBlockReject> {
            if (hash != original->GetHash()) return std::nullopt;
            LOCK(::cs_main);
            CBlock stored;
            BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(stored, *index, false));
            return stored.vchNEVMBlockData == (adopted ? replacement.vchNEVMBlockData : original->vchNEVMBlockData)
                ? permanent : PayloadVerdictFor(stored);
        };
        auto& chainstate{chainman.ActiveChainstate()};
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state), state.ToString());
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, BLOCK_FAILED_VALID);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(index), 1U);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(index), 0U);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == parent->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().HaveCoin(COutPoint{parent->vtx.front()->GetHash(), 0}));
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(COutPoint{original->vtx.front()->GetHash(), 0}));
        BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
        BOOST_CHECK_EQUAL(chainman.ActiveTip()->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        NEVMTxRoot roots;
        BOOST_CHECK(pnevmtxrootsdb->ReadTxRoots(PayloadVerdictFor(*parent).nevm_hash, roots));
        BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(permanent.nevm_hash, roots));
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
        BOOST_CHECK(nevm->applied_hash == parent->GetHash());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
        nevm->connect_verdict = {};
    }
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

struct ProviderParentErrorSetup : StartupNEVMRecoverySetup {
    Consensus::Params& consensus{
        const_cast<Consensus::Params&>(Params().GetConsensus())};
    const int previous_dip3_height{consensus.DIP0003Height};
    const CAmount previous_collateral{nMNCollateralRequired};
    const bool previous_shutdown_on_fatal_error{
        m_node.notifications->m_shutdown_on_fatal_error};

    ProviderParentErrorSetup()
    {
        consensus.DIP0003Height = 101;
        nMNCollateralRequired = 40 * COIN;
        m_node.notifications->m_shutdown_on_fatal_error = false;
    }

    ~ProviderParentErrorSetup()
    {
        consensus.DIP0003Height = previous_dip3_height;
        nMNCollateralRequired = previous_collateral;
        m_node.notifications->m_shutdown_on_fatal_error =
            previous_shutdown_on_fatal_error;
        m_node.exit_status.store(EXIT_SUCCESS);
    }

    void CheckParentErrors()
    {
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        const auto parent{MineNEVMBlock()};
        const auto& funding{m_coinbase_txns.front()};
        CKey owner, voting, collateral, payout;
        for (auto* key : {&owner, &voting, &collateral, &payout}) {
            key->MakeNewKey(true);
        }
        CMutableTransaction registration;
        registration.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
        registration.vin.emplace_back(COutPoint{funding->GetHash(), 0});
        registration.vout.emplace_back(nMNCollateralRequired,
            GetScriptForDestination(PKHash(collateral.GetPubKey())));
        registration.vout.emplace_back(
            funding->vout.at(0).nValue - nMNCollateralRequired - 10000,
            GetScriptForDestination(PKHash(payout.GetPubKey())));
        CProRegTx payload;
        payload.nVersion = CProRegTx::LEGACY_BLS_VERSION;
        payload.collateralOutpoint = COutPoint{uint256{}, 0};
        payload.keyIDOwner = owner.GetPubKey().GetID();
        payload.keyIDVoting = voting.GetPubKey().GetID();
        payload.scriptPayout = GetScriptForDestination(PKHash(payout.GetPubKey()));
        // Historical pre-PQ operator keys are opaque, non-null byte strings.
        std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key{};
        operator_key.fill(1);
        BOOST_REQUIRE(payload.pubKeyOperator.SetBytes(operator_key));
        payload.inputsHash = CalcTxInputsHash(CTransaction{registration});
        SetTxPayload(registration, payload);
        FillableSigningProvider signer;
        signer.AddKey(coinbaseKey);
        SignatureData signature;
        BOOST_REQUIRE(SignSignature(signer, *funding, registration, 0,
                                    SIGHASH_ALL, signature));

        auto block_template{node::BlockAssembler{
            chainstate, nullptr}.CreateNewBlock(CScript{} << OP_TRUE)};
        CBlock block{block_template->block};
        block.vtx.push_back(MakeTransactionRef(registration));
        node::RegenerateCommitments(block, chainman,
                                    block_template->vchCoinbaseCommitmentExtra);
        block.fChecked = false;
        while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) {
            ++block.nNonce;
        }
        const auto candidate{std::make_shared<const CBlock>(std::move(block))};
        CNEVMHeader header;
        BlockValidationState header_state;
        BOOST_REQUIRE(GetNEVMData(header_state, *candidate, header));
        CBlockIndex* candidate_index{nullptr};
        CDeterministicMNList parent_list;
        {
            LOCK(::cs_main);
            BlockValidationState valid_state;
            BOOST_REQUIRE_MESSAGE(TestBlockValidity(valid_state,
                chainman.GetParams(), chainstate, *candidate, chainman.ActiveTip(),
                chainman.m_options.adjusted_time_callback), valid_state.ToString());
            parent_list = deterministicMNManager->GetListForBlock(chainman.ActiveTip());
            BOOST_REQUIRE_EQUAL(parent_list.GetHeight(), 101);
            BlockValidationState accept_state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(candidate, accept_state,
                &candidate_index, true, nullptr, nullptr, true), accept_state.ToString());
            BOOST_REQUIRE(candidate_index != nullptr);
        }
        const auto durable_tip{WITH_LOCK(::cs_main,
            return chainstate.CoinsDB().GetBestBlock())};
        const auto published_tip{pnevmtxrootsdb->GetPublishedTip()};
        const auto nevm_connects{nevm->connected_blocks.size()};
        const COutPoint collateral_output{registration.GetHash(), 0};

        enum class Fault { MISSING, HEIGHT, DATABASE };
        for (const auto fault : {Fault::MISSING, Fault::HEIGHT, Fault::DATABASE}) {
            {
                LOCK(::cs_main);
                auto& db{*deterministicMNManager->m_evoDb};
                if (fault == Fault::MISSING) {
                    db.EraseCache(parent->GetHash());
                } else if (fault == Fault::HEIGHT) {
                    auto mismatch{parent_list};
                    mismatch.SetHeight(parent_list.GetHeight() - 1);
                    db.WriteCache(parent->GetHash(), std::move(mismatch));
                } else {
                    db.EraseCache(uint256S("f001"));
                    db.FailNextFlushBatchForTesting();
                }
            }
            BlockValidationState failed_state;
            BOOST_CHECK(!chainstate.ActivateBestChain(failed_state, candidate));
            BOOST_CHECK(failed_state.IsError());
            BOOST_CHECK(!failed_state.IsInvalid());
            BOOST_CHECK(failed_state.ToString().find("failed-protx-parent-state") !=
                        std::string::npos);
            {
                LOCK(::cs_main);
                BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
                BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(candidate_index), 1U);
                BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == parent->GetHash());
                BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetHash());
                BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_tip);
                BOOST_CHECK(chainstate.CoinsTip().HaveCoin(registration.vin.front().prevout));
                BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(collateral_output));
                deterministicMNManager->m_evoDb->WriteCache(parent->GetHash(), parent_list);
            }
            BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), nevm_connects);
            BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == published_tip);
            NEVMTxRoot roots;
            BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots));
            m_node.exit_status.store(EXIT_SUCCESS);
        }

        // The same fully validated, indexed candidate succeeds after local
        // state is restored, without reconsidering or replacing the block.
        BlockValidationState retry_state;
        BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(retry_state, candidate),
                              retry_state.ToString());
        BOOST_CHECK(retry_state.IsValid());
        {
            LOCK(::cs_main);
            BOOST_CHECK(chainman.ActiveTip() == candidate_index);
            BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_CHECK(chainstate.CoinsTip().HaveCoin(collateral_output));
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(registration.vin.front().prevout));
            BOOST_CHECK(deterministicMNManager->GetListForBlock(candidate_index)
                            .GetMN(registration.GetHash()) != nullptr);
        }
        NEVMTxRoot roots;
        BOOST_CHECK(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots));
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), nevm_connects + 1);
    }
};

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
    std::function<void()> before_root_block;

    explicit NEVMRootRollbackSetup(bool block_tree_db_in_memory = true)
        : StartupNEVMRecoverySetup{/*coins_db_in_memory=*/false,
                                    /*managed_exit=*/false,
                                    block_tree_db_in_memory}
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
            if (before_root_block) before_root_block();
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
        if (before_root_block) before_root_block();
        parent = MineNEVMBlock();
        nevm->template_block_hash.reset();
        SyncWithValidationInterfaceQueue();
        auto& chainman{*m_node.chainman};
        auto& chainstate{chainman.ActiveChainstate()};
        if (before_root_block) before_root_block();
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

// SYSCOIN: A shallow root recovery must coexist with legitimately pruned
// canonical history, including after both the block index and coins reopen.
struct PrunedNEVMRootRecoverySetup : NEVMRootRollbackSetup {
    enum class RecoveryControl { NONE, MISSING_RECENT_BODY, INTERRUPTED };
    std::shared_ptr<const CBlock> old_block;
    CNEVMHeader old_header;
    int pruned_file{-1};

    PrunedNEVMRootRecoverySetup()
        : NEVMRootRollbackSetup{/*block_tree_db_in_memory=*/false}
    {
        before_root_block = [&] {
            const auto* tip{WITH_LOCK(::cs_main, return m_node.chainman->ActiveTip())};
            BOOST_REQUIRE(tip != nullptr);
            BOOST_REQUIRE(governance != nullptr);
            BOOST_REQUIRE(governance_tests::PublishGovernanceReadyForTest(*governance, *tip));
            // The ordinary mock serial wraps at 256. Keep all commitments
            // unique so no accidental alias can terminate the old-body scan.
            nevm->template_block_hash = GetRandHash();
            nevm->template_roots = NEVMTxRoot{GetRandHash(), GetRandHash()};
        };
    }

    ~PrunedNEVMRootRecoverySetup()
    {
        if (governance) governance->ObserveChainTip(nullptr);
    }

    void PreparePrunedRecovery(bool pending_disconnect, bool alias_pruned_root = false)
    {
        auto& chainman{*m_node.chainman};
        auto& blockman{chainman.m_blockman};
        auto& chainstate{chainman.ActiveChainstate()};
        before_root_block();
        old_block = MineNEVMBlock();
        {
            LOCK(::cs_main);
            const auto* old_index{blockman.LookupBlockIndex(old_block->GetHash())};
            BOOST_REQUIRE(old_index != nullptr);
            pruned_file = old_index->GetBlockPos().nFile;
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, *old_block, old_header));
            // Use the existing block-file rollover fixture technique, leaving
            // every subsequently protected block in a different real file.
            blockman.GetBlockFileInfo(pruned_file)->nSize = node::MAX_BLOCKFILE_SIZE;
        }
        for (unsigned int i{0}; i <= MIN_BLOCKS_TO_KEEP; ++i) {
            before_root_block();
            MineNEVMBlock();
        }
        SyncWithValidationInterfaceQueue();
        {
            LOCK(::cs_main);
            const auto* old_index{blockman.LookupBlockIndex(old_block->GetHash())};
            const auto* info{blockman.GetBlockFileInfo(pruned_file)};
            BOOST_REQUIRE_EQUAL(info->nHeightLast, old_index->nHeight);
            BOOST_REQUIRE_LT(info->nHeightLast + MIN_BLOCKS_TO_KEEP,
                             static_cast<unsigned int>(chainman.ActiveHeight()));
            BOOST_REQUIRE(chainman.ActiveTip()->GetBlockPos().nFile != pruned_file);
            BlockValidationState state;
            BOOST_REQUIRE(chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS));
            blockman.PruneOneBlockFile(pruned_file);
            blockman.m_have_pruned = true;
            BOOST_REQUIRE(blockman.m_block_tree_db->WriteFlag("prunedblockfiles", true));
            BOOST_REQUIRE(blockman.WriteBlockIndexDB());
            blockman.UnlinkPrunedFiles({pruned_file});
            BOOST_REQUIRE(blockman.IsBlockPruned(old_index));
            BOOST_CHECK_EQUAL(old_index->nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO), 0U);
            BOOST_CHECK(blockman.OpenBlockFile(FlatFilePos{pruned_file, 0}, true).IsNull());
            for (int height{chainman.ActiveHeight() - static_cast<int>(MIN_BLOCKS_TO_KEEP)};
                 height <= chainman.ActiveHeight(); ++height) {
                const auto* index{chainman.ActiveChain()[height]};
                BOOST_REQUIRE(index->nStatus & BLOCK_HAVE_DATA);
                BOOST_REQUIRE(index->GetBlockPos().nFile != pruned_file);
            }
        }
        std::size_t recent_templates{0};
        const auto prepare_unique{before_root_block};
        before_root_block = [&] {
            prepare_unique();
            if (alias_pruned_root && ++recent_templates == 2) {
                // The discarded carrier aliases the genuinely pruned height
                // 101 commitment, but supplies different roots for that key.
                nevm->template_block_hash = old_header.nBlockHash;
            }
        };
        BOOST_REQUIRE(!alias_pruned_root || pending_disconnect);
        PrepareRootDisconnect(/*with_mint=*/false, /*lagging_coins=*/!pending_disconnect);
        before_root_block = prepare_unique;
        nevm->template_block_hash.reset();
        nevm->template_roots.reset();
        BOOST_REQUIRE(old_header.nBlockHash != canonical_header.nBlockHash);
        BOOST_REQUIRE_EQUAL(old_header.nBlockHash == orphan_header.nBlockHash, alias_pruned_root);
        if (alias_pruned_root) {
            BOOST_REQUIRE(old_header.nTxRoot != orphan_header.nTxRoot);
            BOOST_REQUIRE(old_header.nReceiptRoot != orphan_header.nReceiptRoot);
        }
        MintDB().FlushDataToCache({mint_hash});
        BOOST_REQUIRE(MintDB().FlushCacheToDisk());
        if (pending_disconnect) {
            std::size_t coins_syncs{0};
            RootsDB().before_write = [&] { return coins_syncs == 0; };
            WITH_LOCK(::cs_main, chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
                ++coins_syncs;
                return true;
            }));
            BlockValidationState state;
            const bool disconnected{DisconnectRootTip(state, /*reverify=*/false)};
            RootsDB().before_write = {};
            WITH_LOCK(::cs_main, chainstate.CoinsDB().SetSyncCallbackForTesting({}));
            BOOST_REQUIRE(!disconnected);
            BOOST_REQUIRE_EQUAL(coins_syncs, 1U);
            BOOST_REQUIRE(RootsDB().GetPendingDisconnect());
        } else {
            // This is the same forward root-publication cut as the existing
            // crash fixture: roots are durable while coins still name Q.
            BOOST_REQUIRE(RootsDB().RecordPublishedTip(carrier.GetHash()));
            BOOST_REQUIRE(RootsDB().FlushCacheToDisk());
            BOOST_REQUIRE(!RootsDB().GetPendingDisconnect());
        }
        SyncWithValidationInterfaceQueue();
        LOCK(::cs_main);
        const uint256 recovered{pending_disconnect ? parent->GetHash() : checkpoint->GetHash()};
        BOOST_REQUIRE(chainstate.CoinsDB().GetBestBlock() == recovered);
        BOOST_REQUIRE(chainstate.CoinsDB().GetHeadBlocks().empty());
        for (const auto& hash : {parent->GetHash(), carrier.GetHash()}) {
            const auto* index{blockman.LookupBlockIndex(hash)};
            BOOST_REQUIRE(index != nullptr);
            BOOST_REQUIRE(index->GetBlockPos().nFile != pruned_file);
            CBlock readable;
            BOOST_REQUIRE(blockman.ReadBlockFromDisk(readable, *index, false));
        }
        BOOST_REQUIRE(blockman.FlushChainstateBlockFile(chainman.ActiveHeight()));
        BOOST_REQUIRE(blockman.WriteBlockIndexDB());
        nevm->command_trace.clear();
    }

    void CheckReopenedRecovery(bool pending_disconnect,
                               RecoveryControl control = RecoveryControl::NONE)
    {
        auto& original{*m_node.chainman};
        auto& original_chainstate{original.ActiveChainstate()};
        ChainstateManager reopened{m_node.kernel->interrupt, original.m_options,
            {.chainparams = original.GetParams(),
             .prune_target = BlockManager::PRUNE_TARGET_MANUAL,
             .blocks_dir = m_args.GetBlocksDirPath(),
             .notifications = *m_node.notifications}};
        LOCK(::cs_main);
        const auto coins_path{original_chainstate.CoinsDB().StoragePath()};
        const auto index_path{original.m_blockman.m_block_tree_db->StoragePath()};
        BOOST_REQUIRE(coins_path && index_path);
        auto& recovered{reopened.InitializeChainstate(nullptr)};
        struct RestoreDatabases {
            ChainstateManager& original;
            ChainstateManager& reopened;
            fs::path coins_path;
            ~RestoreDatabases()
            {
                reopened.ActiveChainstate().ResetCoinsViews();
                original.m_blockman.m_block_tree_db = std::move(reopened.m_blockman.m_block_tree_db);
                auto& chainstate{original.ActiveChainstate()};
                chainstate.InitCoinsDB(1U << 20, false, false, coins_path);
                chainstate.InitCoinsCache(1U << 23);
                if (auto* tip{original.m_blockman.LookupBlockIndex(chainstate.CoinsDB().GetBestBlock())}) {
                    chainstate.m_chain.SetTip(*tip);
                }
            }
        } restore{original, reopened, *coins_path};
        original_chainstate.ResetCoinsViews();
        original.m_blockman.m_block_tree_db.reset();
        reopened.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
            .path = *index_path, .cache_bytes = 1U << 20});
        BOOST_REQUIRE(reopened.m_blockman.LoadBlockIndexDB(std::nullopt));
        const auto* old_index{reopened.m_blockman.LookupBlockIndex(old_block->GetHash())};
        BOOST_REQUIRE(old_index != nullptr);
        BOOST_CHECK(old_index != original.m_blockman.LookupBlockIndex(old_block->GetHash()));
        BOOST_REQUIRE(reopened.m_blockman.IsBlockPruned(old_index));
        BOOST_CHECK_EQUAL(old_index->nStatus & BLOCK_FAILED_MASK, 0U);
        recovered.InitCoinsDB(1U << 20, false, false, *coins_path);
        pnevmtxrootsdb.reset();
        pnevmtxrootsdb = std::make_unique<ObservedDisconnectRootsDB>(DBParams{
            .path = roots_path, .cache_bytes = 1U << 20});
        pnevmtxmintdb.reset();
        pnevmtxmintdb = std::make_unique<ObservedRollbackMintDB>(DBParams{
            .path = mints_path, .cache_bytes = 1U << 20});
        const auto& expected{pending_disconnect ? *parent : *checkpoint};
        CNEVMHeader expected_header;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, expected, expected_header));
        BOOST_REQUIRE(recovered.CoinsDB().GetBestBlock() == expected.GetHash());
        BOOST_REQUIRE_EQUAL(RootsDB().GetPendingDisconnect().has_value(), pending_disconnect);
        const auto snapshot_coins = [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            CDataStream bytes{SER_DISK, CLIENT_VERSION};
            bytes << recovered.CoinsDB().GetBestBlock() << recovered.CoinsDB().GetHeadBlocks();
            auto cursor{recovered.CoinsDB().Cursor()};
            for (; cursor->Valid(); cursor->Next()) {
                COutPoint outpoint;
                Coin coin;
                BOOST_REQUIRE(cursor->GetKey(outpoint));
                BOOST_REQUIRE(cursor->GetValue(coin));
                bytes << outpoint << coin;
            }
            return std::vector<std::byte>{bytes.begin(), bytes.end()};
        };
        const auto original_coins{snapshot_coins()};
        const auto original_published{RootsDB().GetPublishedTip()};
        const auto original_pending{RootsDB().GetPendingDisconnect()};
        const auto check_retained_recovery = [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            BOOST_CHECK(snapshot_coins() == original_coins);
            BOOST_CHECK(RootsDB().GetPublishedTip() == original_published);
            const auto pending{RootsDB().GetPendingDisconnect()};
            BOOST_REQUIRE_EQUAL(pending.has_value(), original_pending.has_value());
            if (pending) {
                BOOST_CHECK(pending->carrier == original_pending->carrier);
                BOOST_CHECK(pending->block_hash == original_pending->block_hash);
                BOOST_CHECK(pending->tx_root == original_pending->tx_root);
                BOOST_CHECK(pending->receipt_root == original_pending->receipt_root);
            }
            BOOST_CHECK(MintDB().Exists(mint_hash));
            BOOST_CHECK(MintDB().ExistsTx(mint_hash));
            BOOST_CHECK(!MintDB().ExistsTx(unclaimed_hash));
            BOOST_CHECK(nevm->command_trace.empty());
        };
        if (control == RecoveryControl::MISSING_RECENT_BODY) {
            const auto* index{reopened.m_blockman.LookupBlockIndex(carrier.GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_REQUIRE(index->nStatus & BLOCK_HAVE_DATA);
            BOOST_REQUIRE_GT(index->nHeight, old_index->nHeight + static_cast<int>(MIN_BLOCKS_TO_KEEP));
            // Even a valid extra proof row cannot replace the recent body
            // needed to authenticate a journal or discarded source branch.
            CMutableTransaction coinbase{*carrier.vtx.front()};
            for (auto& input : coinbase.vin) input.scriptWitness.SetNull();
            std::vector<uint256> txids;
            for (const auto& tx : carrier.vtx) txids.push_back(tx->GetHash());
            std::vector<bool> matches(txids.size(), false);
            matches.front() = true;
            node::NEVMPrunedRootProof proof;
            proof.coinbase = MakeTransactionRef(std::move(coinbase));
            proof.merkle_tree = CPartialMerkleTree{txids, matches};
            BOOST_REQUIRE(reopened.m_blockman.m_block_tree_db->WriteNEVMPrunedRootProofs(
                {{carrier.GetHash(), proof}}));
            CNEVMHeader authenticated;
            BOOST_REQUIRE(reopened.m_blockman.ReadNEVMPrunedHeader(authenticated, *index));
            BOOST_CHECK(authenticated.nBlockHash == orphan_header.nBlockHash);
            const fs::path block_path{m_args.GetBlocksDirPath() /
                fs::PathFromString(strprintf("blk%05u.dat", index->GetBlockPos().nFile))};
            const fs::path unavailable_path{fs::PathFromString(
                fs::PathToString(block_path) + ".unavailable")};
            BOOST_REQUIRE(fs::exists(block_path));
            BOOST_REQUIRE(!fs::exists(unavailable_path));
            fs::rename(block_path, unavailable_path);
            {
                struct RestoreBlockFile {
                    fs::path original, unavailable;
                    ~RestoreBlockFile() { fs::rename(unavailable, original); }
                } restore_file{block_path, unavailable_path};
                std::size_t root_writes{0}, coins_writes{0};
                RootsDB().before_write = [&] { ++root_writes; return true; };
                recovered.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
                    ++coins_writes;
                    return true;
                });
                const bool replayed{recovered.ReplayBlocks()};
                RootsDB().before_write = {};
                recovered.CoinsDB().SetWriteBatchCallbackForTesting({});
                BOOST_CHECK(!replayed);
                BOOST_CHECK_EQUAL(root_writes, 0U);
                BOOST_CHECK_EQUAL(coins_writes, 0U);
                check_retained_recovery();
            }
        } else if (control == RecoveryControl::INTERRUPTED) {
            BOOST_REQUIRE(!pending_disconnect);
            for (int attempt{0}; attempt < 2; ++attempt) {
                std::size_t root_writes{0}, completed_writes{0};
                // Let orphan erasure commit, then fail publication of the
                // recovered endpoint. Reopen before each retry to discard RAM.
                RootsDB().before_write = [&] { return ++root_writes == 1; };
                RootsDB().after_write = [&] { ++completed_writes; };
                const bool replayed{recovered.ReplayBlocks()};
                RootsDB().before_write = {};
                RootsDB().after_write = {};
                BOOST_CHECK(!replayed);
                BOOST_CHECK_EQUAL(root_writes, 2U);
                BOOST_CHECK_EQUAL(completed_writes, 1U);
                check_retained_recovery();
                recovered.ResetCoinsViews();
                recovered.InitCoinsDB(1U << 20, false, false, *coins_path);
                pnevmtxrootsdb.reset();
                pnevmtxrootsdb = std::make_unique<ObservedDisconnectRootsDB>(DBParams{
                    .path = roots_path, .cache_bytes = 1U << 20});
                check_retained_recovery();
            }
        }
        BOOST_REQUIRE(recovered.ReplayBlocks());
        BOOST_CHECK(snapshot_coins() == original_coins);
        BOOST_CHECK(recovered.CoinsDB().GetBestBlock() == expected.GetHash());
        BOOST_CHECK(recovered.CoinsDB().GetHeadBlocks().empty());
        BOOST_CHECK(recovered.CoinsDB().HaveCoin(COutPoint{old_block->vtx.front()->GetHash(), 0}));
        BOOST_CHECK(recovered.CoinsDB().HaveCoin(COutPoint{expected.vtx.front()->GetHash(), 0}));
        BOOST_CHECK(!recovered.CoinsDB().HaveCoin(COutPoint{carrier.vtx.front()->GetHash(), 0}));
        BOOST_CHECK(!RootsDB().GetPendingDisconnect());
        BOOST_CHECK(RootsDB().GetPublishedTip() == expected.GetHash());
        NEVMTxRoot root;
        for (const auto* header : {&old_header, &expected_header}) {
            BOOST_REQUIRE(RootsDB().Read(header->nBlockHash, root));
            BOOST_CHECK(root.nTxRoot == header->nTxRoot);
            BOOST_CHECK(root.nReceiptRoot == header->nReceiptRoot);
            BOOST_REQUIRE(RootsDB().ReadTxRoots(header->nBlockHash, root));
            BOOST_CHECK(root.nTxRoot == header->nTxRoot);
            BOOST_CHECK(root.nReceiptRoot == header->nReceiptRoot);
        }
        if (orphan_header.nBlockHash != old_header.nBlockHash) {
            BOOST_CHECK(!RootsDB().Read(orphan_header.nBlockHash, root));
            BOOST_CHECK(!RootsDB().ReadTxRoots(orphan_header.nBlockHash, root));
        }
        if (!pending_disconnect) {
            BOOST_CHECK(!RootsDB().Read(canonical_header.nBlockHash, root));
            BOOST_CHECK(!RootsDB().ReadTxRoots(canonical_header.nBlockHash, root));
        }
        BOOST_CHECK(MintDB().Exists(mint_hash));
        BOOST_CHECK(MintDB().ExistsTx(mint_hash));
        BOOST_CHECK(!MintDB().ExistsTx(unclaimed_hash));
        BOOST_CHECK(nevm->command_trace.empty());

        recovered.ResetCoinsViews();
        recovered.InitCoinsDB(1U << 20, false, false, *coins_path);
        pnevmtxrootsdb.reset();
        pnevmtxrootsdb = std::make_unique<ObservedDisconnectRootsDB>(DBParams{
            .path = roots_path, .cache_bytes = 1U << 20});
        std::size_t root_writes{0}, coins_writes{0};
        RootsDB().before_write = [&] { ++root_writes; return true; };
        recovered.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
            ++coins_writes;
            return true;
        });
        BOOST_CHECK(recovered.ReplayBlocks());
        RootsDB().before_write = {};
        recovered.CoinsDB().SetWriteBatchCallbackForTesting({});
        BOOST_CHECK_EQUAL(root_writes, 0U);
        BOOST_CHECK_EQUAL(coins_writes, 0U);
        BOOST_CHECK(nevm->command_trace.empty());
    }
};

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

// SYSCOIN: Deferred replay must preserve its original marker when a synthetic
// engine verdict causes ordinary invalidation of locally valid fixture blocks.
struct DeferredNEVMRejectionSetup : StartupNEVMRecoverySetup {
    enum class Boundary { CONNECT, INITIAL_FLUSH, FINAL_FLUSH };
    std::shared_ptr<const CBlock> retained, rejected, original_tip, replacement;
    CBlockIndex* rejected_index{nullptr};
    std::size_t verdict_deliveries{0};
    std::size_t finalizations{0};
    bool complete{true};
    bool interrupt_on_verdict{false};
    std::string replay_error;

    ~DeferredNEVMRejectionSetup()
    {
        WITH_LOCK(::cs_main,
            m_node.chainman->ActiveChainstate().CoinsDB().SetSyncCallbackForTesting({}));
        m_node.kernel->interrupt.reset();
    }

    NEVMBlockReject VerdictFor(const CBlock& block)
    {
        CNEVMHeader header;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, block, header));
        return {header.nBlockHash, block.GetHash()};
    }

    void Prepare(bool have_replacement = false)
    {
        auto& chainman{*Assert(m_node.chainman)};
        nevm->strict_connect_order = true;
        retained = MineNEVMBlock();
        if (have_replacement) replacement = MakeNEVMBlock();
        nevm->buffer_connects = true;
        rejected = MineNEVMBlock();
        original_tip = MineNEVMBlock();
        if (replacement) {
            LOCK(::cs_main);
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
                replacement, state, nullptr, /*fRequested=*/true,
                /*dbp=*/nullptr, /*fNewBlock=*/nullptr, /*min_pow_checked=*/true),
                state.ToString());
        }
        {
            LOCK(::cs_main);
            rejected_index = chainman.m_blockman.LookupBlockIndex(rejected->GetHash());
            BOOST_REQUIRE(rejected_index != nullptr);
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainman.ActiveChainstate().FlushStateToDisk(
                state, FlushStateMode::ALWAYS), state.ToString());
        }
        // Retain the last applied pair while the accepted Core suffix awaits
        // delivery. All blocks were produced by the existing valid miner.
        BOOST_REQUIRE_EQUAL(nevm->applied_count, 1U);
        BOOST_REQUIRE(nevm->applied_hash == retained->GetHash());
        nevm->buffered_pairs.clear();
        nevm->buffered_pair.reset();
        nevm->connected_blocks.clear();
        nevm->command_trace.clear();
        nevm->flush_requests = 0;
        nevm->disconnect_error = "unexpected-disconnect-of-unapplied-prefix";
    }

    void DeliverAt(Boundary boundary)
    {
        const auto deliver = [this]() -> std::optional<NEVMBlockReject> {
            BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
            // A replacement on the surviving parent must use normal ordered
            // delivery and advance the fake's applied pair successfully.
            nevm->buffer_connects = false;
            if (interrupt_on_verdict) m_node.kernel->interrupt();
            return VerdictFor(*rejected);
        };
        if (boundary == Boundary::CONNECT) {
            nevm->connect_verdict = [this, deliver](const uint256& hash)
                -> std::optional<NEVMBlockReject> {
                return hash == rejected->GetHash() ? deliver() : std::nullopt;
            };
        } else {
            const std::size_t flush{boundary == Boundary::INITIAL_FLUSH ? 1U : 2U};
            nevm->flush_verdict = [this, flush, deliver]()
                -> std::optional<NEVMBlockReject> {
                return nevm->flush_requests == flush ? deliver() : std::nullopt;
            };
        }
    }

    bool Replay()
    {
        return ReplayDeferredForTest(
            m_node.chainman->ActiveChainstate(), 103, original_tip->GetHash(),
            [this] {
                AssertMainLockHeldForTest();
                ++finalizations;
                return true;
            }, complete, replay_error);
    }

    void CheckRoots(const CBlock& block, bool present)
    {
        CNEVMHeader header;
        BlockValidationState state;
        BOOST_REQUIRE(GetNEVMData(state, block, header));
        NEVMTxRoot roots;
        BOOST_CHECK_EQUAL(pnevmtxrootsdb->ReadTxRoots(header.nBlockHash, roots), present);
        BOOST_CHECK_EQUAL(pnevmtxrootsdb->Read(header.nBlockHash, roots), present);
        if (present) {
            BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
            BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
        }
    }

    void CheckMarkerRetained()
    {
        BOOST_CHECK(!complete);
        BOOST_CHECK_EQUAL(finalizations, 0U);
        BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
        BOOST_CHECK(nevm->disconnected_blocks.empty());
    }

    void CheckRepaired()
    {
        CheckMarkerRetained();
        BOOST_CHECK_EQUAL(replay_error, "deferred-nevm-rejected-prefix-reconciled");
        auto& chainman{*Assert(m_node.chainman)};
        auto& chainstate{chainman.ActiveChainstate()};
        LOCK(::cs_main);
        const auto expected_tip{replacement ? replacement : retained};
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == expected_tip->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == expected_tip->GetHash());
        BOOST_CHECK_EQUAL(nevm->applied_count, replacement ? 2U : 1U);
        BOOST_CHECK(nevm->applied_hash == expected_tip->GetHash());
        BOOST_CHECK(rejected_index->nStatus & BLOCK_FAILED_VALID);
        CDiskBlockIndex disk_root;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
            std::make_pair(uint8_t{'b'}, rejected->GetHash()), disk_root));
        BOOST_CHECK(disk_root.nStatus & BLOCK_FAILED_VALID);
        const auto* retained_index{chainman.m_blockman.LookupBlockIndex(retained->GetHash())};
        BOOST_REQUIRE(retained_index != nullptr);
        BOOST_CHECK_EQUAL(retained_index->nStatus & BLOCK_FAILED_MASK, 0U);
        for (const auto& block : {rejected, original_tip}) {
            const auto* index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK(index->nStatus & BLOCK_FAILED_MASK);
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
                COutPoint{block->vtx.front()->GetHash(), 0}));
            CheckRoots(*block, false);
        }
        BOOST_CHECK(chainstate.CoinsTip().HaveCoin(
            COutPoint{retained->vtx.front()->GetHash(), 0}));
        CheckRoots(*retained, true);
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        if (!replacement) {
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == retained->GetHash());
            BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == retained->GetHash());
        } else {
            BOOST_CHECK_EQUAL(chainman.ActiveTip()->nStatus & BLOCK_FAILED_MASK, 0U);
            BOOST_REQUIRE(!nevm->connected_blocks.empty());
            BOOST_CHECK(nevm->connected_blocks.back() == replacement->GetHash());
            // The new valid connection retains ordinary asynchronous coins
            // persistence; explicitly flush it before checking its disk tip.
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(
                state, FlushStateMode::ALWAYS), state.ToString());
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == replacement->GetHash());
        }
    }
};


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

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_healthy_import_skips_checks,
                        StartupNEVMRecoverySetup)
{
    MineNEVMBlock();
    const auto tip{MineNEVMBlock()};
    std::string error;
    BOOST_REQUIRE(m_node.chainman->DiscoverNEVMPayloadRepair(2, tip->GetHash(), error));
    BOOST_REQUIRE(m_node.chainman->MaybeRecoverNEVMPayload(error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    BOOST_CHECK(!m_node.chainman->HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return m_node.chainman->GetNEVMPayloadRepairRequest()));
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_rejects_wrong_fingerprint,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    DeliverPayloadVerdict(/*correct_fingerprint=*/false);
    BOOST_CHECK(!m_node.chainman->HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return m_node.chainman->GetNEVMPayloadRepairRequest()));
    BOOST_CHECK(!WITH_LOCK(::cs_main,
        return m_node.chainman->m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER)));
    CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_requires_current_request_and_engine_acceptance,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    DeliverPayloadVerdict();
    const auto request{Request()};
    ConfigurePayloadCheck();
    auto stale{request};
    ++stale.generation;
    BlockValidationState stale_state;
    BOOST_CHECK(!m_node.chainman->ProcessNEVMPayloadRepair(stale, replacement_payload, stale_state));
    BOOST_CHECK_EQUAL(stale_state.GetRejectReason(), "nevm-payload-repair-request-stale");
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    const std::vector<uint8_t> unaccepted_payload{0x01};
    BlockValidationState unaccepted_state;
    BOOST_CHECK(!m_node.chainman->ProcessNEVMPayloadRepair(request, unaccepted_payload, unaccepted_state));
    BOOST_CHECK_EQUAL(unaccepted_state.GetRejectReason(), "fixture-payload-rejected");
    BOOST_CHECK(unaccepted_state.IsError());
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
    BOOST_CHECK(Request() == request);
    CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
    CheckLocalState(/*connected=*/false);
    std::string error;
    BOOST_REQUIRE(m_node.chainman->MaybeRecoverNEVMPayload(error));
    BOOST_REQUIRE(m_node.chainman->MaybeRecoverNEVMPayload(error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_preserves_wrapper_undo_and_replays,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    DeliverPayloadVerdict();
    const auto request{Request()};
    ConfigurePayloadCheck();
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ProcessNEVMPayloadRepair(request, replacement_payload, state),
                          state.ToString());
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(m_node.chainman->HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return m_node.chainman->GetNEVMPayloadRepairRequest()));
    CheckStoredPayload(replacement_payload, /*positions_unchanged=*/false);
    CheckLocalState(/*connected=*/false);
    CompleteRepair();
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
    BOOST_CHECK(nevm->payload_checked_blocks == std::vector<uint256>{prefix[1]->GetHash()});
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_repeated_activation_skips_engine_work,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    DeliverPayloadVerdict();
    const auto request{Request()};
    const auto commands{nevm->command_trace};
    const auto connects{nevm->connected_blocks};
    for (int attempt{0}; attempt < 3; ++attempt) {
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-repair-pending");
        BOOST_CHECK(Request() == request);
        CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
        CheckLocalState(/*connected=*/false);
    }
    BOOST_CHECK(nevm->command_trace == commands);
    BOOST_CHECK(nevm->connected_blocks == connects);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_startup_verifies_before_download,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    ConfigurePayloadCheck();
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(m_node.chainman->m_blockman.m_block_tree_db->Write(
            NEVM_PAYLOAD_TEST_MARKER, payload_verdict, /*fSync=*/true));
        BOOST_REQUIRE(m_node.chainman->InitializeNEVMPayloadRepair(error));
        BOOST_CHECK(m_node.chainman->HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!m_node.chainman->GetNEVMPayloadRepairRequest());
    }
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    BOOST_REQUIRE_MESSAGE(m_node.chainman->MaybeRecoverNEVMPayload(error), error);
    const auto request{Request()};
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
    CheckStoredPayload(prefix[1]->vchNEVMBlockData, /*positions_unchanged=*/true);
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ProcessNEVMPayloadRepair(request, replacement_payload, state),
                          state.ToString());
    CompleteRepair();
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 2U);
}

// SYSCOIN BEGIN: Recover old mutable-payload markers through normal invalidity.
BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reopened_marker_with_immutable_proof,
                        ImmutableNEVMPayloadRepairSetup)
{
    Prepare(/*stored_proof=*/true);
    auto& chainman{*m_node.chainman};
    std::string error;
    {
        LOCK(::cs_main);
        // The previous engine misclassified this representation as repairable.
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Write(
            NEVM_PAYLOAD_TEST_MARKER, payload_verdict, /*fSync=*/true));
        const auto db_path{chainman.m_blockman.m_block_tree_db->StoragePath()};
        BOOST_REQUIRE(db_path.has_value());
        chainman.m_blockman.m_block_tree_db.reset();
        chainman.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
            .path = *db_path, .cache_bytes = 1U << 20});
        BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
        BOOST_REQUIRE_MESSAGE(chainman.InitializeNEVMPayloadRepair(error), error);
        BOOST_CHECK(chainman.HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!chainman.GetNEVMPayloadRepairRequest());
        NEVMBlockReject persisted;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == payload_verdict);
    }
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    CheckParent(/*invalid=*/false);
    RecoverAndCheckInvalid(/*replaced=*/false);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_download_persists_immutable_proof_before_replay,
                        ImmutableNEVMPayloadRepairSetup)
{
    Prepare(/*stored_proof=*/false);
    auto& chainman{*m_node.chainman};
    BlockValidationState pending_state;
    BOOST_REQUIRE(!chainman.ActiveChainstate().ActivateBestChain(pending_state, candidate));
    BOOST_CHECK(pending_state.IsError());
    const auto request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(request.has_value());
    nevm->connected_blocks.clear();
    CheckParent(/*invalid=*/false);
    for (unsigned int failure{0}; failure < 3; ++failure) {
        pure_override = permanent_verdict;
        if (failure == 0) pure_override->nevm_hash = GetRandHash();
        if (failure == 1) pure_override->syscoin_hash = GetRandHash();
        pure_unavailable = failure == 2;
        BlockValidationState state;
        BOOST_CHECK(!chainman.ProcessNEVMPayloadRepair(*request, proof_payload, state));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()) == request);
        CheckStored(/*replaced=*/false);
        CheckParent(/*invalid=*/false);
    }
    pure_override.reset();
    pure_unavailable = false;
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNEVMPayloadRepair(*request, proof_payload, state), state.ToString());
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK(chainman.HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()));
    // Pure validation authorizes storing this exact proof, never block invalidity.
    CheckParent(/*invalid=*/false);
    CheckStored(/*replaced=*/true);
    BOOST_CHECK(nevm->connected_blocks.empty());
    RecoverAndCheckInvalid(/*replaced=*/true);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 4U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_count_zero_discovers_immutable_proof,
                        ImmutableNEVMPayloadRepairSetup)
{
    Prepare(/*stored_proof=*/true, /*active_candidate=*/true);
    auto& chainman{*m_node.chainman};
    std::string error;
    BOOST_REQUIRE_MESSAGE(chainman.DiscoverNEVMPayloadRepair(0, uint256{}, error), error);
    BOOST_CHECK(error.empty());
    BOOST_REQUIRE(chainman.HasPendingNEVMPayloadRepair());
    {
        LOCK(::cs_main);
        BOOST_CHECK(!chainman.GetNEVMPayloadRepairRequest());
        BOOST_CHECK(chainman.ActiveTip() == candidate_index);
        BOOST_CHECK(chainman.ActiveChainstate().CoinsTip().GetBestBlock() == candidate->GetHash());
        BOOST_CHECK(chainman.ActiveChainstate().CoinsDB().GetBestBlock() == candidate->GetHash());
        BOOST_CHECK_EQUAL(candidate_index->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(candidate_index), 0U);
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == candidate->GetHash());
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        NEVMBlockReject persisted;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == payload_verdict);
    }
    BOOST_CHECK(fNEVMConnection);
    BOOST_CHECK(nevm->connected_blocks.empty());
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
    RecoverAndCheckInvalid(/*replaced=*/false);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 1U);
}
// SYSCOIN END: Recover old mutable-payload markers through normal invalidity.

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_clears_after_valid_branch_selection,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    const auto candidate{MakeNEVMBlock()};
    const auto alternative{MakeNEVMBlock()};
    BOOST_REQUIRE(candidate->GetHash() != alternative->GetHash());
    BOOST_REQUIRE(candidate->hashPrevBlock == alternative->hashPrevBlock);
    const auto verdict{PayloadVerdictFor(*candidate)};
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* alternative_index{nullptr};
    {
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            candidate, state, &candidate_index, true, nullptr, nullptr, true),
            state.ToString());
        BOOST_REQUIRE(candidate_index != nullptr);
    }
    nevm->connect_verdict = [verdict](const uint256& hash)
        -> std::optional<NEVMBlockReject> {
        return hash == verdict.syscoin_hash ? std::optional{verdict} : std::nullopt;
    };
    BlockValidationState rejected_state;
    BOOST_CHECK(!chainstate.ActivateBestChain(rejected_state, candidate));
    BOOST_CHECK_EQUAL(rejected_state.GetRejectReason(), "nevm-payload-repair-pending");
    const auto request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(request.has_value());
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return chainman.ActiveHeight()), 100);
    std::string error;
    // A target that extends the current tip must remain eligible for repair.
    BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()) == request);
    {
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            alternative, state, &alternative_index, true, nullptr, nullptr, true),
            state.ToString());
        BOOST_REQUIRE(alternative_index != nullptr);
    }
    BlockValidationState selected_state;
    BOOST_REQUIRE_MESSAGE(chainstate.PreciousBlock(selected_state, alternative_index),
                          selected_state.ToString());
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()) == alternative_index);
    const auto commands{nevm->command_trace};
    BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()));
    BOOST_CHECK(!WITH_LOCK(::cs_main,
        return chainman.m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER)));
    BOOST_CHECK_EQUAL(WITH_LOCK(::cs_main, return candidate_index->nStatus & BLOCK_FAILED_MASK), 0U);
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.ActiveTip()) == alternative_index);
    BOOST_CHECK(nevm->command_trace == commands);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
}

// SYSCOIN BEGIN: A selected competing branch can replace a pending payload repair.
BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_switches_to_selected_competing_branch,
                        PersistentNEVMPayloadRepairSetup)
{
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    const auto candidate{MakeNEVMBlock()};
    const auto alternative{MakeNEVMBlock()};
    // Give B a valid stored child without first connecting either sibling.
    // Before DIP3, these templates contain only a coinbase; update its BIP34
    // height while retaining the independently generated NEVM commitment.
    CBlock child{*MakeNEVMBlock()};
    BOOST_REQUIRE_EQUAL(child.vtx.size(), 1U);
    BOOST_REQUIRE_LT(parent->nHeight + 2, chainman.GetConsensus().DIP0003Height);
    CMutableTransaction coinbase{*child.vtx.front()};
    coinbase.vin.front().scriptSig = CScript{} << (parent->nHeight + 2) << OP_0;
    child.vtx.front() = MakeTransactionRef(std::move(coinbase));
    child.hashPrevBlock = alternative->GetHash();
    child.hashMerkleRoot = BlockMerkleRoot(child);
    child.fChecked = false;
    child.nNonce = 0;
    while (!CheckProofOfWork(child.GetHash(), child.nBits, chainman.GetConsensus())) ++child.nNonce;
    const auto alternative_tip{std::make_shared<const CBlock>(std::move(child))};
    const auto candidate_verdict{PayloadVerdictFor(*candidate)};
    const auto alternative_verdict{PayloadVerdictFor(*alternative)};
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* alternative_index{nullptr};
    CBlockIndex* alternative_tip_index{nullptr};
    const auto accept = [&](const auto& block, CBlockIndex*& index) {
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            block, state, &index, true, nullptr, nullptr, true), state.ToString());
        BOOST_REQUIRE(index != nullptr);
    };
    accept(candidate, candidate_index);
    nevm->connect_verdict = [candidate_verdict, alternative_verdict](const uint256& hash)
        -> std::optional<NEVMBlockReject> {
        if (hash == candidate_verdict.syscoin_hash) return candidate_verdict;
        if (hash == alternative_verdict.syscoin_hash) return alternative_verdict;
        return std::nullopt;
    };
    BlockValidationState first_state;
    BOOST_CHECK(!chainstate.ActivateBestChain(first_state, candidate));
    BOOST_CHECK_EQUAL(first_state.GetRejectReason(), "nevm-payload-repair-pending");
    const auto old_request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(old_request.has_value());
    BOOST_REQUIRE(old_request->rejection == candidate_verdict);
    const auto published_parent{pnevmtxrootsdb->GetPublishedTip()};
    accept(alternative, alternative_index);
    accept(alternative_tip, alternative_tip_index);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.ActiveTip() == parent);
        BOOST_REQUIRE(candidate_index->pprev == parent);
        BOOST_REQUIRE(alternative_index->pprev == parent);
        BOOST_REQUIRE(alternative_tip_index->pprev == alternative_index);
        BOOST_REQUIRE(alternative_tip_index->nChainWork > candidate_index->nChainWork);
        BOOST_REQUIRE(chainstate.IsCurrentMostWorkBranch(*alternative_index));
        BOOST_REQUIRE(!(alternative_tip_index->nStatus & BLOCK_CONFLICT_CHAINLOCK));
    }
    BlockValidationState selected_state;
    BOOST_CHECK(!chainstate.ActivateBestChain(selected_state));
    BOOST_CHECK(selected_state.IsError());
    BOOST_CHECK(!selected_state.IsInvalid());
    BOOST_CHECK_EQUAL(selected_state.GetRejectReason(), "nevm-payload-repair-pending");
    BOOST_CHECK(nevm->connected_blocks ==
                (std::vector<uint256>{candidate->GetHash(), alternative->GetHash()}));
    const auto request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(request.has_value());
    BOOST_REQUIRE(request->rejection == alternative_verdict);
    BOOST_CHECK_GT(request->generation, old_request->generation);
    // Reopen the real block index after retargeting. The new obligation must
    // survive independently of the old manager's in-memory repair state.
    SyncWithValidationInterfaceQueue();
    {
        ChainstateManager restarted{m_node.kernel->interrupt, chainman.m_options,
            {.chainparams = chainman.GetParams(),
             .blocks_dir = m_args.GetBlocksDirPath(),
             .notifications = *m_node.notifications}};
        LOCK(::cs_main);
        const auto db_path{chainman.m_blockman.m_block_tree_db->StoragePath()};
        BOOST_REQUIRE(db_path.has_value());
        chainman.m_blockman.m_block_tree_db.reset();
        restarted.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
            .path = *db_path, .cache_bytes = 1U << 20});
        struct RestoreIndexDB {
            BlockManager& original;
            BlockManager& reopened;
            ~RestoreIndexDB() { original.m_block_tree_db = std::move(reopened.m_block_tree_db); }
        } restore{chainman.m_blockman, restarted.m_blockman};
        BOOST_REQUIRE(restarted.m_blockman.LoadBlockIndexDB(std::nullopt));
        for (const auto& block : {candidate, alternative, alternative_tip}) {
            const auto* index{restarted.m_blockman.LookupBlockIndex(block->GetHash())};
            BOOST_REQUIRE(index != nullptr);
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
        }
        std::string error;
        BOOST_REQUIRE_MESSAGE(restarted.InitializeNEVMPayloadRepair(error), error);
        BOOST_CHECK(restarted.HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!restarted.GetNEVMPayloadRepairRequest());
        BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
        NEVMBlockReject persisted;
        BOOST_REQUIRE(restarted.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == alternative_verdict);
    }
    const auto original_pos{WITH_LOCK(::cs_main, return alternative_index->GetBlockPos())};
    const auto check_unpublished = [&]() {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == parent);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetBlockHash());
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent->GetBlockHash());
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == published_parent);
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        for (const auto* index : {candidate_index, alternative_index, alternative_tip_index}) {
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
        }
        for (const auto& block : {candidate, alternative, alternative_tip}) {
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(COutPoint{block->vtx.front()->GetHash(), 0}));
            NEVMTxRoot roots;
            const auto hash{PayloadVerdictFor(*block).nevm_hash};
            BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(hash, roots));
            BOOST_CHECK(!pnevmtxrootsdb->Read(hash, roots));
        }
        NEVMBlockReject persisted;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == alternative_verdict);
        CBlock stored;
        BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(stored, *alternative_index, false));
        BOOST_CHECK(stored.vchNEVMBlockData == alternative->vchNEVMBlockData);
        BOOST_CHECK(alternative_index->GetBlockPos() == original_pos);
        BOOST_CHECK_EQUAL(nevm->applied_count, 0U);
        BOOST_CHECK(nevm->applied_hash.IsNull());
        BOOST_CHECK(nevm->disconnected_blocks.empty());
    };
    check_unpublished();
    const std::vector<uint8_t> replacement{0x51, 0x52};
    BlockValidationState stale_state;
    BOOST_CHECK(!chainman.ProcessNEVMPayloadRepair(*old_request, replacement, stale_state));
    BOOST_CHECK_EQUAL(stale_state.GetRejectReason(), "nevm-payload-repair-request-stale");
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    nevm->payload_check_response = [&](const CNEVMHeader& header, const CBlock& block,
        const uint256& hash, bool& valid, std::string& error, std::optional<NEVMBlockReject>*) {
        BOOST_CHECK(hash == alternative_verdict.syscoin_hash);
        BOOST_CHECK(header.nBlockHash == alternative_verdict.nevm_hash);
        valid = block.vchNEVMBlockData == replacement;
        error = valid ? std::string{} : "fixture-payload-rejected";
    };
    const std::vector<uint8_t> unaccepted{0x00};
    BlockValidationState unaccepted_state;
    BOOST_CHECK(!chainman.ProcessNEVMPayloadRepair(*request, unaccepted, unaccepted_state));
    BOOST_CHECK_EQUAL(unaccepted_state.GetRejectReason(), "fixture-payload-rejected");
    BOOST_CHECK(WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest()) == request);
    check_unpublished();
    BlockValidationState repaired_state;
    BOOST_REQUIRE_MESSAGE(chainman.ProcessNEVMPayloadRepair(*request, replacement, repaired_state),
                          repaired_state.ToString());
    nevm->connect_verdict = {};
    std::string error;
    BOOST_REQUIRE_MESSAGE(chainman.MaybeRecoverNEVMPayload(error), error);
    BOOST_CHECK(error.empty());
    BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 2U);
    BOOST_CHECK(nevm->applied_hash == alternative_tip->GetHash());
    LOCK(::cs_main);
    BOOST_CHECK(chainman.ActiveTip() == alternative_tip_index);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == alternative_tip->GetHash());
    BOOST_CHECK_EQUAL(candidate_index->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK_EQUAL(alternative_index->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK_EQUAL(alternative_tip_index->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER));
}
// SYSCOIN END: A selected competing branch can replace a pending payload repair.

// SYSCOIN BEGIN: Retargeting requires the attempted pair and its stored fingerprint.
BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_retarget_rejects_unrelated_or_changed_payload,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    const auto candidate{MakeNEVMBlock()};
    const auto alternative{MakeNEVMBlock()};
    const auto unrelated{MakeNEVMBlock()};
    CBlock child{*MakeNEVMBlock()};
    BOOST_REQUIRE_EQUAL(child.vtx.size(), 1U);
    BOOST_REQUIRE_LT(parent->nHeight + 2, chainman.GetConsensus().DIP0003Height);
    CMutableTransaction coinbase{*child.vtx.front()};
    coinbase.vin.front().scriptSig = CScript{} << (parent->nHeight + 2) << OP_0;
    child.vtx.front() = MakeTransactionRef(std::move(coinbase));
    child.hashPrevBlock = alternative->GetHash();
    child.hashMerkleRoot = BlockMerkleRoot(child);
    child.fChecked = false;
    child.nNonce = 0;
    while (!CheckProofOfWork(child.GetHash(), child.nBits, chainman.GetConsensus())) ++child.nNonce;
    const auto alternative_tip{std::make_shared<const CBlock>(std::move(child))};
    const auto candidate_verdict{PayloadVerdictFor(*candidate)};
    const auto alternative_verdict{PayloadVerdictFor(*alternative)};
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* alternative_index{nullptr};
    CBlockIndex* unrelated_index{nullptr};
    CBlockIndex* alternative_tip_index{nullptr};
    const auto accept = [&](const auto& block, CBlockIndex*& index) {
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            block, state, &index, true, nullptr, nullptr, true), state.ToString());
        BOOST_REQUIRE(index != nullptr);
    };
    accept(candidate, candidate_index);
    nevm->connect_verdict = [candidate_verdict](const uint256& hash)
        -> std::optional<NEVMBlockReject> {
        return hash == candidate_verdict.syscoin_hash ? std::optional{candidate_verdict} : std::nullopt;
    };
    BlockValidationState first_state;
    BOOST_CHECK(!chainstate.ActivateBestChain(first_state, candidate));
    BOOST_CHECK_EQUAL(first_state.GetRejectReason(), "nevm-payload-repair-pending");
    const auto request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(request.has_value());
    BOOST_REQUIRE(request->rejection == candidate_verdict);
    accept(alternative, alternative_index);
    accept(unrelated, unrelated_index);
    accept(alternative_tip, alternative_tip_index);
    const auto published_parent{pnevmtxrootsdb->GetPublishedTip()};
    const auto original_pos{WITH_LOCK(::cs_main, return alternative_index->GetBlockPos())};
    for (const bool wrong_pair : {true, false}) {
        BOOST_TEST_CONTEXT((wrong_pair ? "unrelated stored sibling" : "changed stored fingerprint")) {
            auto verdict{wrong_pair ? PayloadVerdictFor(*unrelated) : alternative_verdict};
            if (!wrong_pair) verdict.payload_hash->begin()[0] ^= 1;
            nevm->connect_verdict = [&, verdict](const uint256& hash)
                -> std::optional<NEVMBlockReject> {
                BOOST_CHECK(hash == alternative->GetHash());
                return verdict;
            };
            {
                LOCK(::cs_main);
                BOOST_REQUIRE(alternative_tip_index->nChainWork > candidate_index->nChainWork);
                BOOST_REQUIRE(chainstate.IsCurrentMostWorkBranch(*alternative_index));
                BOOST_CHECK(!chainstate.IsCurrentMostWorkBranch(*unrelated_index));
            }
            const auto connects{nevm->connected_blocks.size()};
            BlockValidationState state;
            BOOST_CHECK(!chainstate.ActivateBestChain(state));
            BOOST_CHECK(state.IsError());
            BOOST_CHECK(!state.IsInvalid());
            if (!wrong_pair) BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-repair-fingerprint-mismatch");
            BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 1);
            LOCK(::cs_main);
            BOOST_CHECK(chainman.GetNEVMPayloadRepairRequest() == request);
            BOOST_CHECK(chainman.ActiveTip() == parent);
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetBlockHash());
            BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent->GetBlockHash());
            BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == published_parent);
            BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
            for (const auto* index : {candidate_index, alternative_index, unrelated_index, alternative_tip_index}) {
                BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            }
            for (const auto& block : {candidate, alternative, unrelated, alternative_tip}) {
                BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(COutPoint{block->vtx.front()->GetHash(), 0}));
                NEVMTxRoot roots;
                BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(PayloadVerdictFor(*block).nevm_hash, roots));
            }
            NEVMBlockReject persisted;
            BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
            BOOST_CHECK(persisted == candidate_verdict);
            CBlock stored;
            BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(stored, *alternative_index, false));
            BOOST_CHECK(stored.vchNEVMBlockData == alternative->vchNEVMBlockData);
            BOOST_CHECK(alternative_index->GetBlockPos() == original_pos);
            BOOST_CHECK_EQUAL(nevm->applied_count, 0U);
            BOOST_CHECK(nevm->disconnected_blocks.empty());
            BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
        }
    }
}
// SYSCOIN END: Retargeting requires the attempted pair and its stored fingerprint.

// SYSCOIN BEGIN: Failed retarget persistence preserves the previous durable repair.
BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_retarget_flush_failure_keeps_durable_obligation,
                        FailedNEVMPayloadRetargetSetup)
{
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* const parent{WITH_LOCK(::cs_main, return chainman.ActiveTip())};
    const auto candidate{MakeNEVMBlock()};
    const auto alternative{MakeNEVMBlock()};
    CBlock child{*MakeNEVMBlock()};
    BOOST_REQUIRE_EQUAL(child.vtx.size(), 1U);
    BOOST_REQUIRE_LT(parent->nHeight + 2, chainman.GetConsensus().DIP0003Height);
    CMutableTransaction coinbase{*child.vtx.front()};
    coinbase.vin.front().scriptSig = CScript{} << (parent->nHeight + 2) << OP_0;
    child.vtx.front() = MakeTransactionRef(std::move(coinbase));
    child.hashPrevBlock = alternative->GetHash();
    child.hashMerkleRoot = BlockMerkleRoot(child);
    child.fChecked = false;
    child.nNonce = 0;
    while (!CheckProofOfWork(child.GetHash(), child.nBits, chainman.GetConsensus())) ++child.nNonce;
    const auto alternative_tip{std::make_shared<const CBlock>(std::move(child))};
    const auto candidate_verdict{PayloadVerdictFor(*candidate)};
    const auto alternative_verdict{PayloadVerdictFor(*alternative)};
    CBlockIndex* candidate_index{nullptr};
    CBlockIndex* alternative_index{nullptr};
    CBlockIndex* alternative_tip_index{nullptr};
    const auto accept = [&](const auto& block, CBlockIndex*& index) {
        LOCK(::cs_main);
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(chainman.AcceptBlock(
            block, state, &index, true, nullptr, nullptr, true), state.ToString());
        BOOST_REQUIRE(index != nullptr);
    };
    accept(candidate, candidate_index);
    nevm->connect_verdict = [candidate_verdict, alternative_verdict](const uint256& hash)
        -> std::optional<NEVMBlockReject> {
        if (hash == candidate_verdict.syscoin_hash) return candidate_verdict;
        if (hash == alternative_verdict.syscoin_hash) return alternative_verdict;
        return std::nullopt;
    };
    BlockValidationState first_state;
    BOOST_CHECK(!chainstate.ActivateBestChain(first_state, candidate));
    BOOST_CHECK_EQUAL(first_state.GetRejectReason(), "nevm-payload-repair-pending");
    const auto old_request{WITH_LOCK(::cs_main, return chainman.GetNEVMPayloadRepairRequest())};
    BOOST_REQUIRE(old_request.has_value());
    BOOST_REQUIRE(old_request->rejection == candidate_verdict);
    const auto coins_path{WITH_LOCK(::cs_main, return chainstate.CoinsDB().StoragePath())};
    BOOST_REQUIRE(coins_path.has_value());
    const auto index_path{WITH_LOCK(::cs_main,
        return chainman.m_blockman.m_block_tree_db->StoragePath())};
    BOOST_REQUIRE(index_path.has_value());
    const auto published_parent{pnevmtxrootsdb->GetPublishedTip()};
    accept(alternative, alternative_index);
    accept(alternative_tip, alternative_tip_index);
    std::size_t coins_writes{0};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(alternative_tip_index->nChainWork > candidate_index->nChainWork);
        BOOST_REQUIRE(chainstate.IsCurrentMostWorkBranch(*alternative_index));
        chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
            ++coins_writes;
            BOOST_CHECK(chainman.HasPendingNEVMPayloadRepair());
            BOOST_CHECK(!chainman.GetNEVMPayloadRepairRequest());
            NEVMBlockReject persisted;
            BOOST_CHECK(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
            BOOST_CHECK(persisted == candidate_verdict);
            return false;
        });
    }
    BlockValidationState failed_state;
    const bool activated{chainstate.ActivateBestChain(failed_state)};
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetWriteBatchCallbackForTesting({});
        // A failed coins batch intentionally poisons its view. Reopen the
        // existing disk state before any assertions can abort this test.
        chainstate.ResetCoinsViews();
        chainstate.InitCoinsDB(1U << 20, /*in_memory=*/false,
                               /*should_wipe=*/false, *coins_path);
        chainstate.InitCoinsCache(1U << 23);
        BOOST_CHECK(!activated);
        BOOST_CHECK(failed_state.IsError());
        BOOST_CHECK(!failed_state.IsInvalid());
        BOOST_CHECK_EQUAL(coins_writes, 1U);
        BOOST_CHECK(chainman.ActiveTip() == parent);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == parent->GetBlockHash());
        BOOST_CHECK(chainstate.CoinsDB().GetHeadBlocks().empty());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == parent->GetBlockHash());
        BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == published_parent);
        BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        BOOST_CHECK(chainman.HasPendingNEVMPayloadRepair());
        BOOST_CHECK(!chainman.GetNEVMPayloadRepairRequest());
        NEVMBlockReject persisted;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
        BOOST_CHECK(persisted == candidate_verdict);
        for (const auto* index : {candidate_index, alternative_index, alternative_tip_index}) {
            BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
        }
        for (const auto& block : {candidate, alternative, alternative_tip}) {
            BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(COutPoint{block->vtx.front()->GetHash(), 0}));
            NEVMTxRoot roots;
            BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(PayloadVerdictFor(*block).nevm_hash, roots));
        }
    }
    BlockValidationState stale_state;
    const std::vector<uint8_t> replacement{0x51, 0x52};
    BOOST_CHECK(!chainman.ProcessNEVMPayloadRepair(*old_request, replacement, stale_state));
    BOOST_CHECK_EQUAL(stale_state.GetRejectReason(), "nevm-payload-repair-request-stale");
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
    BOOST_CHECK_EQUAL(nevm->applied_count, 0U);
    BOOST_CHECK(nevm->disconnected_blocks.empty());

    // A fresh manager recovers A from the old durable row, even though the
    // live manager has already switched its nondurable obligation to B.
    SyncWithValidationInterfaceQueue();
    ChainstateManager restarted{m_node.kernel->interrupt, chainman.m_options,
        {.chainparams = chainman.GetParams(),
         .blocks_dir = m_args.GetBlocksDirPath(),
         .notifications = *m_node.notifications}};
    LOCK(::cs_main);
    chainman.m_blockman.m_block_tree_db.reset();
    restarted.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
        .path = *index_path, .cache_bytes = 1U << 20});
    struct RestoreIndexDB {
        BlockManager& original;
        BlockManager& reopened;
        ~RestoreIndexDB() { original.m_block_tree_db = std::move(reopened.m_block_tree_db); }
    } restore{chainman.m_blockman, restarted.m_blockman};
    BOOST_REQUIRE(restarted.m_blockman.LoadBlockIndexDB(std::nullopt));
    std::string error;
    BOOST_REQUIRE_MESSAGE(restarted.InitializeNEVMPayloadRepair(error), error);
    BOOST_CHECK(restarted.HasPendingNEVMPayloadRepair());
    BOOST_CHECK(!restarted.GetNEVMPayloadRepairRequest());
    const auto* restored_candidate{restarted.m_blockman.LookupBlockIndex(candidate->GetHash())};
    const auto* restored_alternative{restarted.m_blockman.LookupBlockIndex(alternative->GetHash())};
    BOOST_REQUIRE(restored_candidate != nullptr);
    BOOST_REQUIRE(restored_alternative != nullptr);
    NEVMBlockReject persisted;
    BOOST_REQUIRE(restarted.m_blockman.m_block_tree_db->Read(NEVM_PAYLOAD_TEST_MARKER, persisted));
    BOOST_CHECK(persisted == candidate_verdict);
}
// SYSCOIN END: Failed retarget persistence preserves the previous durable repair.

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_startup_discards_failed_marker,
                        StartupNEVMRecoverySetup)
{
    auto& chainman{*m_node.chainman};
    const auto block{MineNEVMBlock()};
    const auto verdict{PayloadVerdictFor(*block)};
    CBlockIndex* index{WITH_LOCK(::cs_main,
        return chainman.m_blockman.LookupBlockIndex(block->GetHash()))};
    BOOST_REQUIRE(index != nullptr);
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainman.ActiveChainstate().InvalidateBlock(
        state, index, /*bReverify=*/false), state.ToString());
    const auto commands{nevm->command_trace};
    std::string error;
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(index->nStatus & BLOCK_FAILED_VALID);
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Write(
            NEVM_PAYLOAD_TEST_MARKER, verdict, /*fSync=*/true));
        BOOST_REQUIRE_MESSAGE(chainman.InitializeNEVMPayloadRepair(error), error);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(!chainman.GetNEVMPayloadRepairRequest());
        BOOST_CHECK(!chainman.m_blockman.m_block_tree_db->Exists(NEVM_PAYLOAD_TEST_MARKER));
        BOOST_CHECK(index->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK_EQUAL(chainman.ActiveHeight(), 100);
    }
    BOOST_CHECK(!chainman.HasPendingNEVMPayloadRepair());
    BOOST_CHECK(nevm->command_trace == commands);
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 0U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reorg_skips_unapplied_active_suffix,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/false);
    CheckForkSelected(/*below_applied=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reorg_disconnects_applied_prefix,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/true);
    CheckForkSelected(/*below_applied=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reorg_preserves_state_when_status_unavailable,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/false);
    nevm->flush_available = false;
    CheckRefusedFork("nevm-payload-reorg-status:nevm-flush-unavailable", /*queried=*/false);
    nevm->flush_available = true;
    nevm->block_info_error = "fixture-status-unavailable";
    CheckRefusedFork("nevm-payload-reorg-status:fixture-status-unavailable");
    nevm->block_info_error.clear();
    CheckForkSelected(/*below_applied=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_invalidation_unwinds_exact_applied_prefix,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/true);
    CheckExplicitUnwind(/*conflict=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_conflict_unwinds_exact_applied_prefix,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/true);
    CheckExplicitUnwind(/*conflict=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reorg_requires_exact_applied_endpoint,
                        NEVMPayloadForkSetup)
{
    PrepareFork(/*below_applied=*/false);
    struct RefusedEndpoint {
        const char* name;
        StartupNEVMSubscriber::AppliedPair applied;
        const char* error;
    };
    const std::array<RefusedEndpoint, 5> endpoints{{
        {"zero count with nonzero hash", {0, prefix.front()->GetHash()},
            "nevm-payload-reorg-applied-prefix-mismatch"},
        {"endpoint on competing branch", {2, fork.front()->GetHash()},
            "nevm-payload-reorg-applied-branch-mismatch"},
        {"endpoint hash at wrong height", {2, prefix.front()->GetHash()},
            "nevm-payload-reorg-applied-branch-mismatch"},
        {"endpoint ahead of active tip", {4, candidate->GetHash()},
            "nevm-payload-reorg-applied-prefix-mismatch"},
        {"overflowing applied count", {std::numeric_limits<uint64_t>::max(), prefix.front()->GetHash()},
            "nevm-payload-reorg-applied-prefix-mismatch"}}};
    for (const auto& endpoint : endpoints) {
        BOOST_TEST_CONTEXT(endpoint.name) {
            nevm->reported_pair_override = endpoint.applied;
            CheckRefusedFork(endpoint.error);
        }
    }
    nevm->reported_pair_override.reset();
    CheckForkSelected(/*below_applied=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_startup_replays_published_replacement,
                        NEVMPayloadRepairSetup)
{
    PreparePayloadFixture();
    ConfigurePayloadCheck();
    CBlock corrected{*prefix[1]};
    corrected.vchNEVMBlockData = replacement_payload;
    CNEVMHeader header;
    BlockValidationState state;
    BOOST_REQUIRE(GetNEVMData(state, corrected, header));
    bool valid{false};
    std::string error;
    BOOST_REQUIRE(GetMainSignals().NotifyNEVMPayloadCheck(
        header, corrected, corrected.GetHash(), valid, error));
    BOOST_REQUIRE(valid);
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(m_node.chainman->m_blockman.m_block_tree_db->Write(
            NEVM_PAYLOAD_TEST_MARKER, payload_verdict, /*fSync=*/true));
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReplaceNEVMBlockData(
            state, *repaired_index, replacement_payload));
        // Simulate loss of the in-memory phase after the durable pointer
        // update. Startup must validate the new bytes before deciding to fetch.
        BOOST_REQUIRE(m_node.chainman->InitializeNEVMPayloadRepair(error));
        BOOST_CHECK(!m_node.chainman->GetNEVMPayloadRepairRequest());
    }
    CheckStoredPayload(replacement_payload, /*positions_unchanged=*/false);
    CompleteRepair();
    BOOST_CHECK_EQUAL(nevm->payload_check_requests, 2U);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_marker_survives_index_reopen,
                        PersistentNEVMPayloadRepairSetup)
{
    CheckReopenedMarker(/*replacement_published=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_published_pointer_survives_index_reopen,
                        PersistentNEVMPayloadRepairSetup)
{
    CheckReopenedMarker(/*replacement_published=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_direct_duplicate,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_queued_duplicate,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_identical_skips_check,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/false, /*changed=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_direct_immutable_proof,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/false, /*changed=*/true, ImmutableProof::REPLACEMENT);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_queued_immutable_proof,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/true, /*changed=*/true, ImmutableProof::REPLACEMENT);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_repair_reindex_retains_original_immutable_proof,
                        NEVMPayloadReindexSetup)
{
    CheckReindexDuplicate(/*queued=*/false, /*changed=*/true, ImmutableProof::ORIGINAL);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_operational_errors_preserve_block_candidate,
                        StartupNEVMRecoverySetup)
{
    for (const auto* error : {"nevm-not-connected", "ZMQ_RCVTIMEO",
                             "nevm-connect-not-sent", "nevm-response-invalid-parts",
                             "nevm-response-wrong-command", "nevm-response-not-found",
                             "nevm-connect-protocol-unsupported",
                             "nevm-connect-response-invalid-data"}) {
        BOOST_TEST_CONTEXT(error) { CheckConnectError(error); }
    }
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_engine_rejection_invalidates_block_candidate,
                        StartupNEVMRecoverySetup)
{
    CheckConnectError("nevm-connect-consensus-invalid", /*engine_rejection=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_managed_shutdown_preserves_block_candidate,
                        ManagedNEVMShutdownSetup)
{
    BOOST_REQUIRE(m_node.chainman->GethCommandLine() ==
                  std::vector<std::string>{"--exitwhensynced"});
    for (const auto* error : {"nevm-connect-response-invalid-data",
                             "nevm-connect-consensus-invalid", "nevm-response-not-found",
                             "nevm-connect-protocol-unsupported", "nevm-connect-not-sent"}) {
        BOOST_TEST_CONTEXT(error) {
            CheckConnectError(error, /*engine_rejection=*/false, /*managed_exit=*/true);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_recovers_partial_applied_prefix,
                        LiveNEVMRecoverySetup)
{
    CheckLostPrefix(1, "nevm-connect-response-invalid-data");
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_recovers_zero_applied_prefix,
                        LiveNEVMRecoverySetup)
{
    // A live status response avoids launching a child process while exercising
    // the same recovery path used after a successful managed restart.
    CheckLostPrefix(0, "nevm-connect-not-sent");
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_commits_each_recovery_batch,
                        LiveNEVMRecoverySetup)
{
    CheckLostPrefix(0, "nevm-connect-response-invalid-data", /*acknowledged=*/65);
    // Initial status plus both applied batches, including the one-block tail.
    BOOST_CHECK_EQUAL(nevm->flush_requests, 3U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 3U);
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), 67U);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_accepts_exact_current_pair_after_lost_reply,
                        LiveNEVMRecoverySetup)
{
    PrepareLostPrefix(3);
    nevm->buffer_connects = false;
    nevm->connect_response = [this](const uint256& hash, uint32_t height) {
        BOOST_CHECK(hash == candidate->GetHash());
        BOOST_REQUIRE_LE(++candidate_attempts, 2U);
        if (candidate_attempts == 1) {
            nevm->applied_count = height - 101 + 1;
            nevm->applied_hash = hash;
            return std::string{"nevm-response-not-found"};
        }
        return std::string{};
    };
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate),
                          state.ToString());
    BOOST_CHECK(state.IsValid());
    CheckLocalState(/*connected=*/true);
    BOOST_CHECK_EQUAL(nevm->applied_count, 4U);
    BOOST_CHECK(nevm->applied_hash == candidate->GetHash());
    const std::vector<std::string> expected{
        "connect:" + candidate->GetHash().ToString(), "flush", "blockinfo",
        "connect:" + candidate->GetHash().ToString()};
    BOOST_CHECK(nevm->command_trace == expected);
}

// SYSCOIN: These nonmint blocks are valid before the synthetic engine verdict.
// Exercise only classification and atomic local-state publication at the
// recovery flush boundary; no invalid transaction or engine payload is needed.
BOOST_FIXTURE_TEST_CASE(nevm_connect_live_current_flush_verdict_invalidates_candidate,
                        RejectedNEVMPrefixSetup)
{
    PrepareLostPrefix(3);
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    {
        LOCK(::cs_main);
        BlockValidationState valid_state;
        BOOST_REQUIRE_MESSAGE(TestBlockValidity(
            valid_state, chainman.GetParams(), chainstate, *candidate,
            original_tip, chainman.m_options.adjusted_time_callback),
            valid_state.ToString());
        BlockValidationState flush_state;
        BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(flush_state, FlushStateMode::ALWAYS),
                              flush_state.ToString());
        durable_tip = chainstate.CoinsDB().GetBestBlock();
        BOOST_REQUIRE(durable_tip == original_tip->GetBlockHash());
    }
    const auto verdict{VerdictFor(*candidate)};
    nevm->connect_response = [this](const uint256& hash, uint32_t height) {
        BOOST_REQUIRE(hash == candidate->GetHash());
        BOOST_REQUIRE_EQUAL(++candidate_attempts, 1U);
        BOOST_REQUIRE(nevm->buffered_pairs.empty());
        BOOST_REQUIRE(!nevm->buffered_pair.has_value());
        // Queue the valid current pair, then lose its acknowledgement. The
        // recovery flush supplies the synthetic final verdict for that pair.
        const StartupNEVMSubscriber::AppliedPair queued{height - 101 + 1, hash};
        nevm->buffered_pair = queued;
        nevm->buffered_pairs.push_back(queued);
        return std::string{"nevm-response-not-found"};
    };
    nevm->flush_verdict = [this, verdict]() -> std::optional<NEVMBlockReject> {
        BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
        BOOST_REQUIRE(nevm->buffered_pair.has_value());
        BOOST_CHECK_EQUAL(nevm->buffered_pair->count, prefix.size() + 1);
        BOOST_CHECK(nevm->buffered_pair->hash == candidate->GetHash());
        BOOST_REQUIRE_EQUAL(nevm->buffered_pairs.size(), 1U);
        BOOST_CHECK_EQUAL(nevm->buffered_pairs.front().count, prefix.size() + 1);
        BOOST_CHECK(nevm->buffered_pairs.front().hash == candidate->GetHash());
        return verdict;
    };
    const auto flushes{nevm->flush_requests};
    const auto queries{nevm->block_info_queries};
    BlockValidationState state;
    // Ordinary invalid-candidate retirement resets ActivateBestChain's state.
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state, candidate), state.ToString());
    BOOST_CHECK(state.IsValid());
    CheckLocalState(/*connected=*/false, /*invalid=*/true);
    BOOST_CHECK_EQUAL(candidate_attempts, 1U);
    BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, queries);
    const std::vector<std::string> expected{
        "connect:" + candidate->GetHash().ToString(), "flush"};
    BOOST_CHECK(nevm->command_trace == expected);
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
    BOOST_CHECK(nevm->applied_hash == original_tip->GetBlockHash());
    BOOST_CHECK(nevm->buffered_pairs.empty());
    BOOST_CHECK(!nevm->buffered_pair.has_value());
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(candidate_index), 1U);
        BOOST_CHECK(!(descendant_index->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(
            COutPoint{candidate->vtx.front()->GetHash(), 0}));
    }

    // A later engine acknowledgement would buffer this valid fixture block.
    // The cached verdict must prevent another delivery or local admission.
    nevm->connect_response = {};
    nevm->flush_verdict = {};
    BOOST_REQUIRE(nevm->buffer_connects);
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(retry_state, candidate),
                          retry_state.ToString());
    BOOST_CHECK(retry_state.IsValid());
    BOOST_CHECK(nevm->command_trace == expected);
    BOOST_CHECK(nevm->buffered_pairs.empty());
    BOOST_CHECK(!nevm->buffered_pair.has_value());
    CheckLocalState(/*connected=*/false, /*invalid=*/true);

    LOCK(::cs_main);
    BlockValidationState flush_state;
    BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(flush_state, FlushStateMode::ALWAYS),
                          flush_state.ToString());
    CDiskBlockIndex disk_candidate;
    BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, candidate->GetHash()), disk_candidate));
    BOOST_CHECK_EQUAL(disk_candidate.nStatus & BLOCK_FAILED_MASK, BLOCK_FAILED_VALID);
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_tip);
    BOOST_CHECK(!chainstate.CoinsDB().HaveCoin(
        COutPoint{candidate->vtx.front()->GetHash(), 0}));
    for (const auto& block : prefix) {
        auto* const index{chainman.m_blockman.LookupBlockIndex(block->GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(index), 0U);
        CDiskBlockIndex disk_parent;
        BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
            std::make_pair(uint8_t{'b'}, block->GetHash()), disk_parent));
        BOOST_CHECK_EQUAL(disk_parent.nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK(chainstate.CoinsDB().HaveCoin(
            COutPoint{block->vtx.front()->GetHash(), 0}));
        NEVMTxRoot roots;
        const auto parent_verdict{VerdictFor(*block)};
        BOOST_CHECK(pnevmtxrootsdb->Read(parent_verdict.nevm_hash, roots));
        CNEVMHeader header;
        BlockValidationState header_state;
        BOOST_REQUIRE(GetNEVMData(header_state, *block, header));
        BOOST_CHECK(roots.nTxRoot == header.nTxRoot);
        BOOST_CHECK(roots.nReceiptRoot == header.nReceiptRoot);
    }
    NEVMTxRoot candidate_roots;
    BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(verdict.nevm_hash, candidate_roots));
    BOOST_CHECK(!pnevmtxrootsdb->Read(verdict.nevm_hash, candidate_roots));
    BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == durable_tip);
    BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_current_flush_requires_matching_verdict,
                        RejectedNEVMPrefixSetup)
{
    PrepareLostPrefix(3);
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    {
        LOCK(::cs_main);
        BlockValidationState valid_state;
        BOOST_REQUIRE_MESSAGE(TestBlockValidity(
            valid_state, chainman.GetParams(), chainstate, *candidate,
            original_tip, chainman.m_options.adjusted_time_callback),
            valid_state.ToString());
    }
    const auto current{VerdictFor(*candidate)};
    const auto parent{VerdictFor(*prefix.back())};
    struct FlushResult {
        const char* name;
        std::optional<NEVMBlockReject> verdict;
    };
    const std::array<FlushResult, 4> results{{
        {"no structured verdict", std::nullopt},
        {"current Syscoin hash with another NEVM hash",
            NEVMBlockReject{parent.nevm_hash, current.syscoin_hash}},
        {"current NEVM hash with another Syscoin hash",
            NEVMBlockReject{current.nevm_hash, parent.syscoin_hash}},
        {"zero identity", NEVMBlockReject{}}}};
    for (const auto& result : results) {
        BOOST_TEST_CONTEXT(result.name) {
            candidate_attempts = 0;
            verdict_deliveries = 0;
            nevm->command_trace.clear();
            FailFirstCandidate("nevm-response-not-found");
            nevm->flush_available = false;
            nevm->flush_verdict = [this, verdict = result.verdict]()
                -> std::optional<NEVMBlockReject> {
                BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
                return verdict;
            };
            const auto flushes{nevm->flush_requests};
            const auto queries{nevm->block_info_queries};
            BlockValidationState state;
            BOOST_CHECK(!chainstate.ActivateBestChain(state, candidate));
            BOOST_CHECK(state.IsError());
            BOOST_CHECK(!state.IsInvalid());
            CheckLocalState(/*connected=*/false);
            BOOST_CHECK_EQUAL(candidate_attempts, 1U);
            BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
            BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
            BOOST_CHECK_EQUAL(nevm->block_info_queries, queries);
            const std::vector<std::string> expected{
                "connect:" + candidate->GetHash().ToString(), "flush"};
            BOOST_CHECK(nevm->command_trace == expected);
            BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
            BOOST_CHECK(nevm->applied_hash == original_tip->GetBlockHash());
            BOOST_CHECK(nevm->buffered_pairs.empty());
            BOOST_CHECK(!nevm->buffered_pair.has_value());
            LOCK(::cs_main);
            BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(candidate_index), 0U);
            BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        }
    }
    // All four failed flushes preserve ordinary retry eligibility.
    nevm->connect_response = {};
    nevm->flush_verdict = {};
    nevm->flush_available = true;
    nevm->buffer_connects = false;
    nevm->command_trace.clear();
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(retry_state, candidate),
                          retry_state.ToString());
    BOOST_CHECK(retry_state.IsValid());
    CheckLocalState(/*connected=*/true);
    BOOST_CHECK(nevm->command_trace == std::vector<std::string>{
        "connect:" + candidate->GetHash().ToString()});
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size() + 1);
    BOOST_CHECK(nevm->applied_hash == candidate->GetHash());
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_current_flush_verdict_honors_managed_exit,
                        ManagedLiveNEVMRecoverySetup)
{
    PrepareLostPrefix(3);
    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    BOOST_REQUIRE(chainman.GethCommandLine() ==
                  std::vector<std::string>{"--exitwhensynced"});
    {
        LOCK(::cs_main);
        BlockValidationState valid_state;
        BOOST_REQUIRE_MESSAGE(TestBlockValidity(
            valid_state, chainman.GetParams(), chainstate, *candidate,
            original_tip, chainman.m_options.adjusted_time_callback),
            valid_state.ToString());
    }
    CNEVMHeader header;
    BlockValidationState header_state;
    BOOST_REQUIRE(GetNEVMData(header_state, *candidate, header));
    const NEVMBlockReject verdict{header.nBlockHash, candidate->GetHash()};
    std::size_t verdict_deliveries{0};
    // This transport error enters recovery without requesting managed exit.
    FailFirstCandidate("nevm-response-invalid-parts");
    nevm->flush_verdict = [&verdict_deliveries, verdict]()
        -> std::optional<NEVMBlockReject> {
        BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
        return verdict;
    };
    const auto flushes{nevm->flush_requests};
    const auto queries{nevm->block_info_queries};
    BlockValidationState state;
    BOOST_CHECK(!chainstate.ActivateBestChain(state, candidate));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-connect-consensus-invalid");
    BOOST_CHECK(ShutdownRequested());
    CheckLocalState(/*connected=*/false);
    BOOST_CHECK_EQUAL(candidate_attempts, 1U);
    BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, flushes + 1);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, queries);
    const std::vector<std::string> expected{
        "connect:" + candidate->GetHash().ToString(), "flush"};
    BOOST_CHECK(nevm->command_trace == expected);
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
    BOOST_CHECK(nevm->applied_hash == original_tip->GetBlockHash());
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.m_failed_blocks.count(candidate_index), 0U);
    }
    nevm->connect_response = {};
    nevm->flush_verdict = {};
    AbortShutdown();
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_refuses_mismatched_applied_pair,
                        LiveNEVMRecoverySetup)
{
    const auto sibling{MakeNEVMBlock()};
    PrepareLostPrefix(1);
    const std::array<StartupNEVMSubscriber::AppliedPair, 3> mismatches{{
        {1, sibling->GetHash()}, {0, prefix.front()->GetHash()},
        {5, candidate->GetHash()}}};
    for (const auto& pair : mismatches) {
        nevm->reported_pair_override = pair;
        candidate_attempts = 0;
        FailFirstCandidate("nevm-connect-response-invalid-data");
        const auto connects{nevm->connected_blocks.size()};
        const auto queries{nevm->block_info_queries};
        BlockValidationState state;
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 1);
        BOOST_CHECK_EQUAL(nevm->block_info_queries, queries + 1);
        BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
        CheckLocalState(/*connected=*/false);
    }
    nevm->reported_pair_override.reset();
    candidate_attempts = 0;
    FailFirstCandidate("nevm-connect-response-invalid-data");
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate),
                          state.ToString());
    CheckLocalState(/*connected=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_replay_error_does_not_recurse,
                        LiveNEVMRecoverySetup)
{
    PrepareLostPrefix(0);
    nevm->connect_response = [this](const uint256& hash, uint32_t) {
        // Fail fast if recovery attempts to recover recursively from replay.
        BOOST_REQUIRE_LE(nevm->connected_blocks.size(), 3U);
        if (hash == candidate->GetHash()) return std::string{"nevm-connect-response-invalid-data"};
        if (hash == prefix[1]->GetHash()) return std::string{"nevm-response-not-found"};
        return std::string{};
    };
    BlockValidationState state;
    BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
    BOOST_CHECK(state.IsError());
    CheckLocalState(/*connected=*/false);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 1U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, 1U);
    const std::vector<uint256> failed_requests{
        candidate->GetHash(), prefix[0]->GetHash(), prefix[1]->GetHash()};
    BOOST_CHECK(nevm->connected_blocks == failed_requests);
    BOOST_REQUIRE_EQUAL(nevm->buffered_pairs.size(), 1U);

    // The next attempt flushes the earlier acknowledgement, queries the fresh
    // pair, and resumes after it without replaying the same predecessor.
    nevm->connected_blocks.clear();
    FailFirstCandidate("nevm-connect-response-invalid-data");
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(retry_state, candidate),
                          retry_state.ToString());
    const std::vector<uint256> resumed_requests{
        candidate->GetHash(), prefix[1]->GetHash(), prefix[2]->GetHash(), candidate->GetHash()};
    BOOST_CHECK(nevm->connected_blocks == resumed_requests);
    CheckLocalState(/*connected=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_requires_exact_replay_commit_pair,
                        LiveNEVMRecoverySetup)
{
    PrepareLostPrefix(1);
    FailFirstCandidate("nevm-connect-response-invalid-data");
    const auto response{nevm->connect_response};
    nevm->connect_response = [this, response](const uint256& hash, uint32_t height) {
        if (hash == prefix.back()->GetHash()) {
            // The replay ACK and flush succeed, but the reported pair does
            // not yet attest the full accepted parent. Do not retry current.
            nevm->reported_pair_override = StartupNEVMSubscriber::AppliedPair{
                2, prefix[1]->GetHash()};
        }
        return response(hash, height);
    };
    BlockValidationState state;
    BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-live-recovery-commit-pair-mismatch");
    BOOST_CHECK_EQUAL(candidate_attempts, 1U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, 2U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 2U);
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
    const std::vector<uint256> expected{
        candidate->GetHash(), prefix[1]->GetHash(), prefix[2]->GetHash()};
    BOOST_CHECK(nevm->connected_blocks == expected);
    CheckLocalState(/*connected=*/false);

    nevm->reported_pair_override.reset();
    nevm->connect_response = {};
    nevm->buffer_connects = false;
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(retry_state, candidate),
                          retry_state.ToString());
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), expected.size() + 1);
    CheckLocalState(/*connected=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_current_retry_error_is_bounded,
                        LiveNEVMRecoverySetup)
{
    PrepareLostPrefix(1);
    FailFirstCandidate("nevm-connect-response-invalid-data", "nevm-response-not-found");
    BlockValidationState state;
    BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-response-not-found");
    BOOST_CHECK_EQUAL(candidate_attempts, 2U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 2U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, 2U);
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
    CheckLocalState(/*connected=*/false);

    nevm->connect_response = {};
    const auto queries{nevm->block_info_queries};
    const auto connects{nevm->connected_blocks.size()};
    BlockValidationState retry_state;
    BOOST_REQUIRE_MESSAGE(m_node.chainman->ActiveChainstate().ActivateBestChain(retry_state, candidate),
                          retry_state.ToString());
    BOOST_CHECK_EQUAL(nevm->block_info_queries, queries);
    BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 1);
    CheckLocalState(/*connected=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_current_retry_invalidity_is_preserved,
                        LiveNEVMRecoverySetup)
{
    PrepareLostPrefix(1);
    FailFirstCandidate("nevm-connect-response-invalid-data", "nevm-connect-consensus-invalid");
    BlockValidationState state;
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
    BOOST_CHECK_EQUAL(candidate_attempts, 2U);
    BOOST_CHECK_EQUAL(nevm->block_info_queries, 2U);
    BOOST_CHECK_EQUAL(nevm->flush_requests, 2U);
    BOOST_CHECK_EQUAL(nevm->applied_count, prefix.size());
    CheckLocalState(/*connected=*/false, /*invalid=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_connect_live_managed_shutdown_never_recovers_prefix,
                        ManagedLiveNEVMRecoverySetup)
{
    PrepareLostPrefix(1);
    nevm->status_available = false;
    for (const auto* error : {"nevm-connect-response-invalid-data", "nevm-response-not-found",
                             "nevm-connect-not-sent", "nevm-connect-consensus-invalid",
                             "nevm-connect-protocol-unsupported"}) {
        BOOST_TEST_CONTEXT(error) {
            nevm->connect_error = error;
            const auto connects{nevm->connected_blocks.size()};
            BlockValidationState state;
            BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
            BOOST_CHECK(state.IsError());
            BOOST_CHECK_EQUAL(state.GetRejectReason(), error);
            BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), connects + 1);
            BOOST_CHECK_EQUAL(nevm->status_requests, 0U);
            BOOST_CHECK_EQUAL(nevm->flush_requests, 0U);
            BOOST_CHECK_EQUAL(nevm->block_info_queries, 0U);
            BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
            CheckLocalState(/*connected=*/false);
            BOOST_CHECK(ShutdownRequested());
            AbortShutdown();
        }
    }
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_reconciles_initial_connect_verdict,
                        RejectedNEVMPrefixSetup)
{
    CheckBoundary(Boundary::INITIAL_CONNECT);
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_reconciles_exact_replay_verdict,
                        RejectedNEVMPrefixSetup)
{
    CheckBoundary(Boundary::DIRECT_REPLAY);
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_reconciles_initial_flush_verdict,
                        RejectedNEVMPrefixSetup)
{
    CheckBoundary(Boundary::INITIAL_FLUSH);
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_reconciles_batch_flush_verdict,
                        RejectedNEVMPrefixSetup)
{
    CheckBoundary(Boundary::BATCH_FLUSH);
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_reconciles_zero_applied_first_block,
                        RejectedNEVMPrefixSetup)
{
    PrepareRejection();
    nevm->applied_count = 0;
    nevm->applied_hash.SetNull();
    nevm->applied_pairs.clear();
    const auto verdict{VerdictFor(*prefix.front())};
    nevm->connect_verdict = [this, verdict](const uint256& hash)
        -> std::optional<NEVMBlockReject> {
        if (hash != candidate->GetHash()) return std::nullopt;
        BOOST_REQUIRE_EQUAL(++verdict_deliveries, 1U);
        return verdict;
    };

    auto& chainman{*Assert(m_node.chainman)};
    auto& chainstate{chainman.ActiveChainstate()};
    CBlockIndex* rejected_index{nullptr};
    const CBlockIndex* surviving_parent{nullptr};
    {
        LOCK(::cs_main);
        rejected_index = chainman.m_blockman.LookupBlockIndex(prefix.front()->GetHash());
        BOOST_REQUIRE(rejected_index != nullptr);
        surviving_parent = rejected_index->pprev;
        BOOST_REQUIRE(surviving_parent != nullptr);
        BOOST_REQUIRE_EQUAL(surviving_parent->nHeight, 100);
    }

    // The engine's empty applied prefix is the exact predecessor of the
    // first NEVM block, so every acknowledged NEVM block is unapplied.
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state, candidate), state.ToString());
    BOOST_CHECK(state.IsValid());
    LOCK(::cs_main);
    BOOST_CHECK(chainman.ActiveTip() == surviving_parent);
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == surviving_parent->GetBlockHash());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == surviving_parent->GetBlockHash());
    BOOST_CHECK_EQUAL(surviving_parent->nStatus & BLOCK_FAILED_MASK, 0U);
    BOOST_CHECK(rejected_index->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(!(candidate_index->nStatus & BLOCK_FAILED_VALID));
    CDiskBlockIndex disk_root;
    BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, rejected_index->GetBlockHash()), disk_root));
    BOOST_CHECK(disk_root.nStatus & BLOCK_FAILED_VALID);
    for (const auto& block : prefix) {
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
            COutPoint{block->vtx.front()->GetHash(), 0}));
        NEVMTxRoot roots;
        const auto nevm_hash{VerdictFor(*block).nevm_hash};
        BOOST_CHECK(!pnevmtxrootsdb->ReadTxRoots(nevm_hash, roots));
        BOOST_CHECK(!pnevmtxrootsdb->Read(nevm_hash, roots));
    }
    BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
    BOOST_CHECK_EQUAL(nevm->applied_count, 0U);
    BOOST_CHECK(nevm->applied_hash.IsNull());
    BOOST_CHECK(nevm->applied_pairs.empty());
    BOOST_REQUIRE(nevm->last_reported_pair.has_value());
    BOOST_CHECK_EQUAL(nevm->last_reported_pair->count, 0U);
    BOOST_CHECK(nevm->last_reported_pair->hash.IsNull());
    BOOST_CHECK(nevm->buffered_pairs.empty());
    BOOST_CHECK(!nevm->buffered_pair.has_value());
    BOOST_CHECK(nevm->disconnected_blocks.empty());
    BOOST_CHECK(nevm->connected_blocks == std::vector<uint256>{candidate->GetHash()});
    BOOST_CHECK_EQUAL(verdict_deliveries, 1U);
}

BOOST_FIXTURE_TEST_CASE(nevm_rejected_prefix_requires_matching_verdict_and_applied_pair,
                        RejectedNEVMPrefixSetup)
{
    PrepareRejection();
    const auto rejected{VerdictFor(*prefix[1])};
    const auto unrelated{MakeNEVMBlock()};
    const auto unrelated_verdict{VerdictFor(*unrelated)};
    struct RefusedResult {
        const char* name;
        NEVMBlockReject verdict;
        std::optional<StartupNEVMSubscriber::AppliedPair> applied;
    };
    const std::array<RefusedResult, 6> results{{
        {"different committed NEVM hash",
            {unrelated_verdict.nevm_hash, rejected.syscoin_hash}, std::nullopt},
        {"unrelated Syscoin pair", unrelated_verdict, std::nullopt},
        {"applied endpoint on another branch", rejected,
            StartupNEVMSubscriber::AppliedPair{1, unrelated->GetHash()}},
        {"applied endpoint includes rejected block", rejected,
            StartupNEVMSubscriber::AppliedPair{2, prefix[1]->GetHash()}},
        {"applied endpoint is behind the rejected predecessor", rejected,
            StartupNEVMSubscriber::AppliedPair{0, uint256{}}},
        {"zero count with nonzero endpoint", rejected,
            StartupNEVMSubscriber::AppliedPair{0, prefix.front()->GetHash()}}}};
    for (const auto& result : results) {
        BOOST_TEST_CONTEXT(result.name) {
            nevm->reported_pair_override = result.applied;
            nevm->connect_verdict = [this, verdict = result.verdict](const uint256& hash)
                -> std::optional<NEVMBlockReject> {
                BOOST_CHECK(hash == candidate->GetHash());
                return verdict;
            };
            const auto requests{nevm->connected_blocks.size()};
            BlockValidationState state;
            BOOST_CHECK(!m_node.chainman->ActiveChainstate().ActivateBestChain(state, candidate));
            BOOST_CHECK(state.IsError());
            BOOST_CHECK(!state.IsInvalid());
            BOOST_CHECK_EQUAL(nevm->connected_blocks.size(), requests + 1);
            CheckLocalState(/*connected=*/false);
            BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
            BOOST_CHECK(nevm->applied_hash == prefix.front()->GetHash());
            BOOST_REQUIRE_EQUAL(nevm->applied_pairs.size(), 1U);
            for (const auto& block : prefix) {
                NEVMTxRoot roots;
                BOOST_CHECK(pnevmtxrootsdb->Read(VerdictFor(*block).nevm_hash, roots));
            }
            BOOST_CHECK(pnevmtxrootsdb->GetPublishedTip() == original_tip->GetBlockHash());
            BOOST_CHECK(!pnevmtxrootsdb->GetPendingDisconnect());
        }
    }
    nevm->reported_pair_override.reset();
    nevm->connect_verdict = {};
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

BOOST_FIXTURE_TEST_CASE(provider_parent_errors_preserve_block_candidate,
                        ProviderParentErrorSetup)
{
    CheckParentErrors();
}

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

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_pending_disconnect,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/true);
    CheckReopenedRecovery(/*pending_disconnect=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_surplus_published_tip,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/false);
    CheckReopenedRecovery(/*pending_disconnect=*/false);
}

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_restores_canonical_alias,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/true, /*alias_pruned_root=*/true);
    NEVMTxRoot root;
    BOOST_REQUIRE(!RootsDB().Read(old_header.nBlockHash, root));
    BOOST_REQUIRE(!RootsDB().ReadTxRoots(old_header.nBlockHash, root));
    CheckReopenedRecovery(/*pending_disconnect=*/true);
}

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_requires_recent_disconnect_body,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/true);
    CheckReopenedRecovery(/*pending_disconnect=*/true, RecoveryControl::MISSING_RECENT_BODY);
}

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_requires_recent_discarded_body,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/false);
    CheckReopenedRecovery(/*pending_disconnect=*/false, RecoveryControl::MISSING_RECENT_BODY);
}

BOOST_FIXTURE_TEST_CASE(nevm_root_recovery_pruned_retries_interrupted_cleanup,
                        PrunedNEVMRootRecoverySetup)
{
    PreparePrunedRecovery(/*pending_disconnect=*/false);
    CheckReopenedRecovery(/*pending_disconnect=*/false, RecoveryControl::INTERRUPTED);
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

// SYSCOIN BEGIN: Root publication must flush a distinct assumed block stream.
BOOST_FIXTURE_TEST_CASE(nevm_root_publication_requires_distinct_blockfile_flush,
                        NEVMRootRollbackSetup)
{
    auto& chainman{*m_node.chainman};
    auto& chainstate{chainman.ActiveChainstate()};
    auto& blockman{chainman.m_blockman};
    BOOST_REQUIRE(!ShutdownRequested());
    const auto previous_snapshot_height{
        WITH_LOCK(::cs_main, return blockman.m_snapshot_height)};
    struct Restore {
        std::function<void()> action;
        ~Restore() { action(); }
    } restore_snapshot{[&] {
        LOCK(::cs_main);
        blockman.m_snapshot_height = previous_snapshot_height;
    }};
    // PrepareRootDisconnect builds Q, P and A. Put only A in the assumed
    // stream, using the same cursor setup as the blockmanager by-type test.
    WITH_LOCK(::cs_main, blockman.m_snapshot_height = chainman.ActiveHeight() + 3);
    PrepareRootDisconnect(/*with_mint=*/false, /*lagging_coins=*/true);

    LOCK(::cs_main);
    CBlockIndex* const carrier_index{blockman.LookupBlockIndex(carrier.GetHash())};
    CBlockIndex* const parent_index{blockman.LookupBlockIndex(parent->GetHash())};
    BOOST_REQUIRE(carrier_index != nullptr);
    BOOST_REQUIRE(parent_index != nullptr);
    BOOST_REQUIRE_EQUAL(carrier_index->nHeight, *blockman.m_snapshot_height);
    BOOST_REQUIRE_NE(parent_index->nFile, carrier_index->nFile);
    const auto previous_published_tip{RootsDB().GetPublishedTip()};
    const uint256 durable_coins{chainstate.CoinsDB().GetBestBlock()};
    std::size_t root_writes{0};
    std::size_t coins_writes{0};
    {
        const fs::path block_path{blockman.GetBlockPosFilename(carrier_index->GetBlockPos())};
        const fs::path saved_path{fs::u8path(fs::PathToString(block_path) + ".flush-test")};
        fs::rename(block_path, saved_path);
        Restore restore_file{[&] {
            fs::remove(block_path);
            fs::rename(saved_path, block_path);
        }};
        BOOST_REQUIRE(fs::create_directory(block_path));
        const bool previous_shutdown_on_fatal_error{
            m_node.notifications->m_shutdown_on_fatal_error};
        Restore restore_flush_state{[&] {
            LOCK(::cs_main);
            RootsDB().before_write = {};
            chainstate.CoinsDB().SetWriteBatchCallbackForTesting({});
            chainstate.m_chain.SetTip(*carrier_index);
            m_node.notifications->m_shutdown_on_fatal_error = previous_shutdown_on_fatal_error;
            AbortShutdown();
            m_node.exit_status.store(EXIT_SUCCESS);
        }};
        // ConnectTip updates CoinsTip before m_chain. The same Chainstate
        // can therefore require both cursors at the snapshot-height boundary.
        chainstate.m_chain.SetTip(*parent_index);
        BOOST_REQUIRE(chainstate.CoinsTip().GetBestBlock() == carrier.GetHash());
        RootsDB().before_write = [&] { ++root_writes; return true; };
        chainstate.CoinsDB().SetWriteBatchCallbackForTesting([&](bool) {
            ++coins_writes;
            return true;
        });
        m_node.notifications->m_shutdown_on_fatal_error = false;
        BlockValidationState state;
        const bool flushed{chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS)};
        BOOST_CHECK(!flushed);
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "Failed to persist NEVM root publication branch");
        BOOST_CHECK_EQUAL(root_writes, 0U);
        BOOST_CHECK_EQUAL(coins_writes, 0U);
        BOOST_CHECK(RootsDB().GetPublishedTip() == previous_published_tip);
        BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == durable_coins);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == carrier.GetHash());
    }
    // With the actual file restored, the pending roots and coins can commit.
    BlockValidationState state;
    BOOST_REQUIRE_MESSAGE(chainstate.FlushStateToDisk(state, FlushStateMode::ALWAYS),
                          state.ToString());
    BOOST_REQUIRE(RootsDB().GetPublishedTip());
    BOOST_CHECK(*RootsDB().GetPublishedTip() == carrier.GetHash());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == carrier.GetHash());
}
// SYSCOIN END: Root publication preserves the distinct-stream durability barrier.

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

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_connect_preserves_original_marker,
                        DeferredNEVMRejectionSetup)
{
    Prepare();
    DeliverAt(Boundary::CONNECT);
    // A reconciled obsolete replay target does not finalize its marker.
    BOOST_CHECK(!Replay());
    CheckRepaired();
    BOOST_CHECK(nevm->connected_blocks == std::vector<uint256>{rejected->GetHash()});
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_initial_flush_preserves_original_marker,
                        DeferredNEVMRejectionSetup)
{
    Prepare();
    DeliverAt(Boundary::INITIAL_FLUSH);
    BOOST_CHECK(!Replay());
    CheckRepaired();
    BOOST_CHECK(nevm->connected_blocks.empty());
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_final_flush_preserves_original_marker,
                        DeferredNEVMRejectionSetup)
{
    Prepare();
    DeliverAt(Boundary::FINAL_FLUSH);
    BOOST_CHECK(!Replay());
    CheckRepaired();
    BOOST_CHECK(nevm->connected_blocks ==
                (std::vector<uint256>{rejected->GetHash(), original_tip->GetHash()}));
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_selects_valid_replacement,
                        DeferredNEVMRejectionSetup)
{
    Prepare(/*have_replacement=*/true);
    DeliverAt(Boundary::FINAL_FLUSH);
    BOOST_CHECK(!Replay());
    CheckRepaired();
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_interrupt_before_undo_preserves_state,
                        DeferredNEVMRejectionSetup)
{
    Prepare();
    interrupt_on_verdict = true;
    DeliverAt(Boundary::CONNECT);
    BOOST_CHECK(!Replay());
    BOOST_CHECK(!replay_error.empty());
    CheckMarkerRetained();
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    LOCK(::cs_main);
    BOOST_CHECK(m_node.chainman->ActiveTip()->GetBlockHash() == original_tip->GetHash());
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == original_tip->GetHash());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == original_tip->GetHash());
    for (const auto& block : {retained, rejected, original_tip}) {
        const auto* index{m_node.chainman->m_blockman.LookupBlockIndex(block->GetHash())};
        BOOST_REQUIRE(index != nullptr);
        BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
        BOOST_CHECK(chainstate.CoinsTip().HaveCoin(
            COutPoint{block->vtx.front()->GetHash(), 0}));
        CheckRoots(*block, true);
    }
}

BOOST_FIXTURE_TEST_CASE(deferred_nevm_rejection_interrupt_after_undo_retains_marker,
                        DeferredNEVMRejectionSetup)
{
    Prepare();
    DeliverAt(Boundary::CONNECT);
    std::size_t syncs{0};
    auto& chainstate{m_node.chainman->ActiveChainstate()};
    {
        LOCK(::cs_main);
        chainstate.CoinsDB().SetSyncCallbackForTesting([&] {
            if (++syncs == 1) m_node.kernel->interrupt();
            return true;
        });
    }
    BOOST_CHECK(!Replay());
    WITH_LOCK(::cs_main, chainstate.CoinsDB().SetSyncCallbackForTesting({}));
    BOOST_CHECK(!replay_error.empty());
    CheckMarkerRetained();
    BOOST_CHECK_EQUAL(syncs, 1U);
    LOCK(::cs_main);
    // The existing invalidation worker can stop after a descendant. Its
    // caller must not claim completed rejection while the root remains active.
    BOOST_CHECK(m_node.chainman->ActiveTip() == rejected_index);
    BOOST_CHECK(!(rejected_index->nStatus & BLOCK_FAILED_VALID));
    BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == rejected->GetHash());
    BOOST_CHECK(chainstate.CoinsDB().GetBestBlock() == rejected->GetHash());
    CheckRoots(*retained, true);
    CheckRoots(*rejected, true);
    CheckRoots(*original_tip, false);
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
        COutPoint{original_tip->vtx.front()->GetHash(), 0}));
    BOOST_CHECK_EQUAL(nevm->applied_count, 1U);
    BOOST_CHECK(nevm->applied_hash == retained->GetHash());
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

BOOST_FIXTURE_TEST_CASE(reindex_interrupt_during_final_activation_retains_marker,
                        FreshNEVMStartupSetup)
{
    auto& chainman{*Assert(m_node.chainman)};
    BOOST_REQUIRE(!chainman.m_interrupt);
    struct RestoreImportState {
        node::NodeContext& node_context;
        const bool reindex{node::fReindex.load()};
        const bool reindex_geth{fReindexGeth.load()};
        const int sync_mode{masternodeSync.GetAssetID()};
        const bool shutdown_on_fatal_error{
            node_context.notifications->m_shutdown_on_fatal_error};
        const int exit_status{node_context.exit_status.load()};
        ~RestoreImportState()
        {
            node_context.kernel->interrupt.reset();
            node::fReindex = reindex;
            fReindexGeth = reindex_geth;
            masternodeSync.SetSyncMode(sync_mode);
            node_context.notifications->m_shutdown_on_fatal_error =
                shutdown_on_fatal_error;
            node_context.exit_status.store(exit_status);
        }
    } restore{m_node};
    node::fReindex = false;
    fReindexGeth = false;
    masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Start through the real full-reindex loader with an empty block index
    // and its on-disk marker. It also resets the auxiliary replay databases.
    node::ChainstateLoadOptions options;
    options.mempool = m_node.mempool.get();
    options.block_tree_db_in_memory = false;
    options.coins_db_in_memory = true;
    options.reindex = true;
    options.connman = m_node.connman.get();
    options.banman = m_node.banman.get();
    options.peerman = m_node.peerman.get();
    const auto [status, load_error]{
        node::LoadChainstate(chainman, m_cache_sizes, options)};
    BOOST_REQUIRE_MESSAGE(status == node::ChainstateLoadStatus::SUCCESS,
                          load_error.original);
    BOOST_REQUIRE(node::fReindex.load());

    const auto blocks{CreateBlockChain(2, Params())};
    const uint256 genesis_hash{chainman.GetConsensus().hashGenesisBlock};
    {
        LOCK(::cs_main);
        BOOST_REQUIRE(chainman.BlockIndex().empty());
        BOOST_REQUIRE(chainman.ActiveTip() == nullptr);
        BOOST_REQUIRE(chainman.ActiveChainstate().CoinsTip().GetBestBlock().IsNull());
        bool reindexing{false};
        chainman.m_blockman.m_block_tree_db->ReadReindexing(reindexing);
        BOOST_REQUIRE(reindexing);
        // Store only raw records. ImportBlocks must discover every index and
        // candidate itself, activating genesis while it scans this file.
        BOOST_REQUIRE(!chainman.m_blockman.SaveBlockToDisk(
            Params().GenesisBlock(), 0, nullptr).IsNull());
        for (std::size_t i{0}; i < blocks.size(); ++i) {
            const FlatFilePos pos{chainman.m_blockman.SaveBlockToDisk(
                *blocks[i], static_cast<int>(i + 1), nullptr)};
            BOOST_REQUIRE(!pos.IsNull());
            BOOST_REQUIRE_EQUAL(pos.nFile, 0);
        }
        BOOST_REQUIRE(chainman.BlockIndex().empty());
    }

    std::vector<uint256> notified_tips;
    bool suffix_scanned_before_interrupt{false};
    const boost::signals2::scoped_connection tip_notification{
        uiInterface.NotifyBlockTip_connect(
            [&](SynchronizationState, const CBlockIndex* tip) {
                BOOST_REQUIRE(tip != nullptr);
                notified_tips.push_back(tip->GetBlockHash());
                LOCK(::cs_main);
                if (tip->nHeight == 0) {
                    BOOST_CHECK(tip->GetBlockHash() == genesis_hash);
                    BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(
                        blocks.front()->GetHash()) == nullptr);
                    BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(
                        blocks.back()->GetHash()) == nullptr);
                    BOOST_CHECK(!chainman.m_interrupt);
                    return;
                }
                BOOST_CHECK_EQUAL(tip->nHeight, 1);
                BOOST_CHECK(tip->GetBlockHash() == blocks.front()->GetHash());
                const CBlockIndex* suffix{chainman.m_blockman.LookupBlockIndex(
                    blocks.back()->GetHash())};
                suffix_scanned_before_interrupt = suffix != nullptr &&
                    (suffix->nStatus & BLOCK_HAVE_DATA) &&
                    suffix->IsValid(BLOCK_VALID_TRANSACTIONS) &&
                    !suffix->IsValid(BLOCK_VALID_SCRIPTS);
                // Reindex activates only genesis while scanning. Both child
                // records are now indexed, so this is the final ABC call.
                BOOST_CHECK(suffix_scanned_before_interrupt);
                m_node.kernel->interrupt();
            })};

    node::ImportBlocks(chainman, {}, nullptr, deterministicMNManager,
                       activeMasternodeManager, g_wallet_init_interface, m_node);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    BOOST_CHECK(notified_tips ==
        (std::vector<uint256>{genesis_hash, blocks.front()->GetHash()}));
    BOOST_CHECK(suffix_scanned_before_interrupt);
    BOOST_CHECK(chainman.m_interrupt);
    BOOST_CHECK(!chainman.m_blockman.m_importing.load());
    BOOST_CHECK(node::fReindex.load());
    SyncWithValidationInterfaceQueue();
    {
        LOCK(::cs_main);
        auto& chainstate{chainman.ActiveChainstate()};
        BOOST_REQUIRE(chainman.ActiveTip() != nullptr);
        BOOST_CHECK(chainman.ActiveTip()->GetBlockHash() == blocks.front()->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == blocks.front()->GetHash());
        BOOST_CHECK(chainstate.CoinsTip().HaveCoin(
            COutPoint{blocks.front()->vtx.front()->GetHash(), 0}));
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
            COutPoint{blocks.back()->vtx.front()->GetHash(), 0}));
        CBlockIndex* suffix{chainman.m_blockman.LookupBlockIndex(blocks.back()->GetHash())};
        BOOST_REQUIRE(suffix != nullptr);
        BOOST_CHECK(suffix->IsValid(BLOCK_VALID_TRANSACTIONS));
        BOOST_CHECK(!suffix->IsValid(BLOCK_VALID_SCRIPTS));
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(suffix), 1U);

        // Reopen the actual block-tree DB to verify the restart marker, not
        // merely the process flag after ABC returned with a partial prefix.
        chainman.m_blockman.m_block_tree_db.reset();
        chainman.m_blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(DBParams{
            .path = chainman.m_options.datadir / "blocks" / "index",
            .cache_bytes = static_cast<size_t>(m_cache_sizes.block_tree_db),
            .memory_only = false});
        bool reindexing{false};
        chainman.m_blockman.m_block_tree_db->ReadReindexing(reindexing);
        BOOST_CHECK(reindexing);
    }
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

enum class DurableSideBranchCase {
    ACTIVE_VALIDATED,
    BOOTSTRAP_VALIDATED,
    FINISHED_REINDEX_PROVISIONAL,
    DIVERGENT_PROVISIONAL,
    AUDIT_CHECKPOINT_REBUILD,
    AUDIT_CHECKPOINT_GETH_ONLY,
    AUDIT_CHECKPOINT_EMPTY_GETH,
    AUDIT_CHECKPOINT_FULL_REINDEX,
};

// A fsynced side-branch winner protects both its own ancestry and the active
// recovery fork before Start() has imported it into the in-memory store,
// including when activation quarantines an incompatible inactive candidate.
static void CheckPreimportDurableSideBranchBoundary(
    node::NodeContext& node_context, DurableSideBranchCase scenario,
    const node::CacheSizes* load_cache_sizes = nullptr)
{
    const bool audit_checkpoint{
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_REBUILD ||
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_GETH_ONLY ||
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_EMPTY_GETH ||
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_FULL_REINDEX};
    const bool preserve_audit_checkpoint{
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_GETH_ONLY};
    const bool persisted_full_reindex{
        scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_FULL_REINDEX};
    const bool bootstrap_empty_chain{
        scenario == DurableSideBranchCase::BOOTSTRAP_VALIDATED ||
        scenario == DurableSideBranchCase::FINISHED_REINDEX_PROVISIONAL ||
        (audit_checkpoint && !preserve_audit_checkpoint)};
    const bool provisional_winner{
        scenario == DurableSideBranchCase::FINISHED_REINDEX_PROVISIONAL ||
        scenario == DurableSideBranchCase::DIVERGENT_PROVISIONAL};
    struct RestoreReindex {
        const bool previous{node::fReindex.load()};
        const bool previous_geth{fReindexGeth.load()};
        ~RestoreReindex()
        {
            node::fReindex = previous;
            fReindexGeth = previous_geth;
        }
    } restore_reindex;
    auto& chainman{static_cast<TestChainstateManager&>(
        *Assert(node_context.chainman))};
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

    // Retained real blocks must replay under the same pre-DIP rules used to
    // mine them. Preparation can start there and still precede the synthetic
    // winner's first roster cutoff.
    consensus.DIP0003Height = bootstrap_empty_chain || audit_checkpoint ? restore.dip3_height : 1;
    consensus.nPQPreparationHeight = consensus.DIP0003Height;
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
    const int32_t initializer_height{
        config->chainlock_schedule.epoch_origin +
        static_cast<int32_t>(llmq::pq::PQ_FIRST_ELIGIBLE_TARGET_OFFSET)};
    int32_t target_height{initializer_height};
    constexpr uint32_t checkpoint_epoch{llmq::pq::ACTIVE_QUORUMS - 1};
    std::optional<llmq::pq::PaymentAuditEpochSchedule> audit_schedule;
    if (audit_checkpoint) {
        BOOST_REQUIRE(load_cache_sizes != nullptr);
        audit_schedule = llmq::pq::BuildPaymentAuditEpochSchedule(
            {config->chainlock_schedule, config->btcc_schedule}, checkpoint_epoch);
        BOOST_REQUIRE(audit_schedule);
        const auto covered_target{llmq::pq::NextEligibleChainLockTargetHeight(
            config->chainlock_schedule, audit_schedule->carrier_end_height_exclusive - 2)};
        BOOST_REQUIRE(covered_target);
        target_height = *covered_target;
        BOOST_REQUIRE(target_height > initializer_height);
        BOOST_REQUIRE(target_height + 1 >= audit_schedule->carrier_end_height_exclusive);
    }
    BOOST_REQUIRE(llmq::pq::IsEligibleChainLockTarget(
        config->chainlock_schedule, target_height));

    // Register the normal parent-to-child edges so conflict marking exercises
    // its real subtree traversal. These structural entries must never be read
    // as blocks: activation stops at preflight or after the real genesis.
    const auto add_index = [&](const CBlockIndex& parent)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = parent.GetBlockHash();
        header.hashMerkleRoot = GetRandHash();
        header.nTime = parent.nTime + 1;
        header.nBits = parent.nBits;
        CBlockIndex* index{chainman.m_blockman.AddToBlockIndex(
            header, chainman.m_best_header)};
        BOOST_REQUIRE(index != nullptr);
        index->nTx = 1;
        index->nChainTx = parent.nChainTx + 1;
        index->nStatus = (provisional_winner ? BLOCK_VALID_TRANSACTIONS :
                                               BLOCK_VALID_SCRIPTS) | BLOCK_HAVE_DATA;
        if (audit_checkpoint) {
            index->nStatus |= BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
            index->pqPaymentProbationStateHash =
                deterministicMNManager->EmptyPaymentProbationStateHash();
        }
        return index;
    };

    CBlockIndex* durable_target{active_lca};
    CBlockIndex* durable_ancestor{nullptr};
    CBlockIndex* activation_predecessor{nullptr};
    {
        LOCK(::cs_main);
        for (int32_t height{active_lca->nHeight + 1};
             height <= target_height; ++height) {
            durable_target = add_index(*durable_target);
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
        BOOST_REQUIRE(durable_target->IsValid(provisional_winner ?
            BLOCK_VALID_TRANSACTIONS : BLOCK_VALID_SCRIPTS));
        BOOST_CHECK_EQUAL(durable_target->IsValid(BLOCK_VALID_SCRIPTS), !provisional_winner);
    }

    llmq::pq::FinalChainLock winner;
    const CBlockIndex* initializer_target{durable_target->GetAncestor(initializer_height)};
    BOOST_REQUIRE(initializer_target != nullptr);
    winner.statement.height = initializer_target->nHeight;
    winner.statement.block_hash = initializer_target->GetBlockHash();
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
    winner.statement.payment_probation_state_hash = audit_checkpoint
        ? deterministicMNManager->EmptyPaymentProbationStateHash() : GetRandHash();
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
    SyncWithValidationInterfaceQueue();
    llmq::StopLLMQSystem();
    llmq::DestroyLLMQSystem();
    chainman.ResetIbd(PQHistoryAuthState::UNINITIALIZED);
    llmq::pq::RecoveryUniverseCapsulePtr recovery_universe;
    uint256 initializer_logical_id;
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
        recovery_universe = MakeRecoveryUniverseFixture(
            consensus.hashGenesisBlock,
            winner.statement.roster_beacons.active.recovery_authority_source,
            *source_snapshot);
        BOOST_REQUIRE(recovery_universe);
        BOOST_REQUIRE(persistence.PersistInitializedBest(
            winner, context, /*error=*/nullptr, /*verified_reset=*/nullptr,
            /*payment_audit_seal_context=*/std::nullopt,
            recovery_universe));
        if (audit_checkpoint) {
            // Retain the exact initializer as roster authority, then persist
            // a later KEEP winner whose completed audit window can be pruned.
            const auto initializer{winner};
            initializer_logical_id = initializer.GetLogicalId(consensus.hashGenesisBlock);
            auto& statement{winner.statement};
            statement.height = durable_target->nHeight;
            statement.block_hash = durable_target->GetBlockHash();
            statement.previous_chainlock_height = statement.height - llmq::pq::PQ_CL_PERIOD;
            statement.previous_chainlock_hash = durable_target
                ->GetAncestor(statement.previous_chainlock_height)->GetBlockHash();
            statement.roster_transition = llmq::pq::RosterAuthorizationTransitionKind::KEEP;
            statement.roster_authorization_base = {
                initializer.statement.height, initializer.statement.block_hash,
                initializer_logical_id};
            statement.previous_btcc_cursor = initializer.statement.accepted_btcc_cursor;
            statement.btcc_advance = llmq::pq::BTCCAdvance::KEEP;
            llmq::pq::RosterAuthorizationTransition transition;
            transition.kind = statement.roster_transition;
            transition.target_height = statement.height;
            transition.target_block_hash = statement.block_hash;
            transition.predecessor_height = statement.previous_chainlock_height;
            transition.predecessor_block_hash = statement.previous_chainlock_hash;
            transition.authorization_base = statement.roster_authorization_base;
            transition.previous = llmq::pq::RosterAuthorizationPriorState{
                initializer.statement.roster_authorization_state_hash,
                initializer.statement.roster_beacons};
            transition.new_window = statement.roster_beacons;
            const auto state_hash{llmq::pq::GetRosterAuthorizationStateHash(
                consensus.hashGenesisBlock, transition)};
            BOOST_REQUIRE(state_hash);
            statement.roster_authorization_state_hash = *state_hash;
            BOOST_REQUIRE(winner.IsStructurallyValid());
            const auto later_context{llmq::pq::ChainLockStoreTestContextFactory::CreateDurable(
                consensus.hashGenesisBlock, config->chainlock_schedule, statement)};
            BOOST_REQUIRE(later_context);
            BOOST_REQUIRE(persistence.PersistBest(winner, later_context));
        }
    }
    CBlockIndex* genesis{nullptr};
    std::array<CBlockIndex*, 2> bootstrap_competitor{};
    std::optional<llmq::pq::PaymentAuditStoreCheckpoint> checkpoint;
    std::optional<llmq::pq::PaymentAuditFrozenRowSummary> frozen_row;
    if (audit_checkpoint) {
        checkpoint = llmq::pq::PaymentAuditStoreCheckpoint{
            checkpoint_epoch, winner.statement.height, winner.statement.block_hash,
            winner.statement.payment_audit_receipt_state,
            winner.statement.payment_probation_state_hash,
            winner.statement.height, winner.statement.block_hash,
            winner.GetLogicalId(consensus.hashGenesisBlock),
            winner.GetWitnessId(consensus.hashGenesisBlock)};
        BOOST_REQUIRE(checkpoint->IsStructurallyValid());
        {
            llmq::pq::PaymentAuditStore archive{
                chainman.m_options.datadir / "llmq/pq-payment-audits",
                consensus.hashGenesisBlock, 8U << 20, /*wipe=*/true};
            BOOST_REQUIRE(archive.PruneThroughCheckpoint(*checkpoint));
            BOOST_REQUIRE(archive.GetPruneCheckpoint() == checkpoint);
            BOOST_REQUIRE(!archive.GetPendingPruneCheckpoint());
        }
        {
            llmq::pq::PaymentAuditStagingStore staging{
                chainman.m_options.datadir / "llmq/pq-payment-audit-staging",
                consensus.hashGenesisBlock, 8U << 20, /*wipe=*/true};
            llmq::pq::PaymentAuditStagingRow row;
            row.expected.epoch = checkpoint_epoch;
            row.expected.response_height = audit_schedule->rows.front().response_height;
            row.expected.response_chainlock_logical_id = initializer_logical_id;
            row.expected.subject_descriptor_hash = GetRandHash();
            row.deadline_height = audit_schedule->rows.front().deadline_height;
            row.response_block_hash = initializer_target->GetBlockHash();
            BOOST_REQUIRE_EQUAL(row.expected.response_height, initializer_target->nHeight);
            for (std::size_t member{0}; member < llmq::pq::QUORUM_MIN_VALID; ++member) {
                row.subject_valid_members[member / 8] |=
                    static_cast<uint8_t>(uint8_t{1} << (member % 8));
            }
            BOOST_REQUIRE(row.IsStructurallyValid(consensus.hashGenesisBlock));
            using StagingResult = llmq::pq::PaymentAuditStagingResult;
            BOOST_REQUIRE(staging.ActivateEpoch(checkpoint_epoch) == StagingResult::ACCEPTED);
            BOOST_REQUIRE(staging.EnsureRow(row) == StagingResult::ACCEPTED);
            const CBlockIndex* deadline{durable_target->GetAncestor(row.deadline_height)};
            BOOST_REQUIRE(deadline != nullptr);
            BOOST_REQUIRE(staging.FreezeRow(checkpoint_epoch, 0,
                row.response_block_hash, deadline->GetBlockHash()) == StagingResult::ACCEPTED);
            frozen_row = staging.GetSummary(checkpoint_epoch, 0);
            BOOST_REQUIRE(frozen_row);
        }

        {
            LOCK(::cs_main);
            BOOST_REQUIRE(!node::fReindex.load());
            BOOST_REQUIRE(active_tip->nHeight < consensus.DIP0003Height);
            genesis = chainman.m_blockman.LookupBlockIndex(consensus.hashGenesisBlock);
            BOOST_REQUIRE(genesis != nullptr);
            if (bootstrap_empty_chain) {
                bootstrap_competitor[0] = add_index(*durable_ancestor);
                bootstrap_competitor[1] = add_index(*bootstrap_competitor[0]);
                BOOST_REQUIRE(bootstrap_competitor.back()->nChainWork > durable_target->nChainWork);
            }
            BlockValidationState flush_state;
            BOOST_REQUIRE_MESSAGE(chainman.ActiveChainstate().FlushStateToDisk(
                flush_state, FlushStateMode::ALWAYS), flush_state.ToString());
            BOOST_REQUIRE(chainman.ActiveChainstate().CoinsDB().GetBestBlock() == active_tip->GetBlockHash());
            BOOST_REQUIRE(chainman.m_blockman.WriteBlockIndexDB());
            bool full_reindex{false};
            chainman.m_blockman.m_block_tree_db->ReadReindexing(full_reindex);
            BOOST_REQUIRE(!full_reindex);
            if (persisted_full_reindex) {
                BOOST_REQUIRE(chainman.m_blockman.m_block_tree_db->WriteReindexing(true));
            }
            chainman.ResetChainstates();
            // The loader rebuilds this multimap; keep the existing index
            // objects but avoid duplicating their parent-to-child edges.
            chainman.m_blockman.m_prev_block_index.clear();
            if (scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_EMPTY_GETH) {
                auto& empty{chainman.InitializeChainstate(node_context.mempool.get())};
                empty.InitCoinsDB(1U << 20, /*in_memory=*/false, /*should_wipe=*/true);
                BOOST_REQUIRE(empty.CoinsDB().GetBestBlock().IsNull());
                chainman.ResetChainstates();
            }
        }
        node::ChainstateLoadOptions options;
        options.mempool = node_context.mempool.get();
        options.block_tree_db_in_memory = false;
        options.coins_db_in_memory = false;
        options.reindex_chainstate = scenario == DurableSideBranchCase::AUDIT_CHECKPOINT_REBUILD;
        options.fReindexGeth = !persisted_full_reindex;
        options.connman = node_context.connman.get();
        options.banman = node_context.banman.get();
        options.peerman = node_context.peerman.get();
        fReindexGeth = options.fReindexGeth;
        const auto [status, load_error]{node::LoadChainstate(chainman, *load_cache_sizes, options)};
        BOOST_REQUIRE_MESSAGE(status == node::ChainstateLoadStatus::SUCCESS, load_error.original);
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(node::fReindex.load(), persisted_full_reindex);
        BOOST_REQUIRE(chainman.m_blockman.LookupBlockIndex(winner.statement.block_hash) == durable_target);
        if (bootstrap_empty_chain) {
            BOOST_REQUIRE(chainman.ActiveTip() == nullptr);
            BOOST_REQUIRE(chainman.ActiveChainstate().CoinsTip().GetBestBlock().IsNull());
            BOOST_REQUIRE(chainman.ActiveChainstate().CoinsDB().GetHeadBlocks().empty());
            BOOST_REQUIRE(!chainman.ActiveChainstate().CoinsDB().Cursor()->Valid());
        } else {
            BOOST_REQUIRE(chainman.ActiveTip() == active_tip);
            BOOST_REQUIRE(chainman.ActiveChainstate().CoinsDB().GetBestBlock() == active_tip->GetBlockHash());
            BOOST_REQUIRE(chainman.ActiveChainstate().CoinsDB().Cursor()->Valid());
        }
    }
    const auto check_audit_stores = [&] {
        BOOST_REQUIRE(audit_checkpoint);
        SyncWithValidationInterfaceQueue();
        llmq::StopLLMQSystem();
        llmq::DestroyLLMQSystem();
        llmq::pq::PaymentAuditStore archive{
            chainman.m_options.datadir / "llmq/pq-payment-audits", consensus.hashGenesisBlock};
        BOOST_REQUIRE(archive.IsHealthy());
        BOOST_CHECK(!archive.GetPendingPruneCheckpoint());
        BOOST_CHECK(archive.GetPruneCheckpoint() == (preserve_audit_checkpoint
            ? checkpoint : std::optional<llmq::pq::PaymentAuditStoreCheckpoint>{}));
        llmq::pq::PaymentAuditStagingStore staging{
            chainman.m_options.datadir / "llmq/pq-payment-audit-staging", consensus.hashGenesisBlock};
        BOOST_REQUIRE(staging.IsHealthy());
        BOOST_CHECK(staging.ActiveEpoch() == (preserve_audit_checkpoint
            ? std::optional<uint32_t>{checkpoint_epoch} : std::optional<uint32_t>{}));
        BOOST_CHECK(staging.GetSummary(checkpoint_epoch, 0) == (preserve_audit_checkpoint
            ? frozen_row : std::optional<llmq::pq::PaymentAuditFrozenRowSummary>{}));
        llmq::pq::PQChainLockPersistence persistence{
            DBParams{.path = chainman.m_options.datadir / "llmq/pq-chainlocks",
                     .cache_bytes = 4U << 20, .wipe_data = false},
            consensus.hashGenesisBlock, *config};
        const auto persisted_winner{persistence.LoadBest()};
        BOOST_REQUIRE(persisted_winner);
        BOOST_CHECK(persisted_winner->ChainLock() == winner);
        const auto persisted_universe{persistence.LoadRecoveryUniverse(recovery_universe->SourceId())};
        BOOST_REQUIRE(persisted_universe);
        BOOST_CHECK(persisted_universe->CapsuleId() == recovery_universe->CapsuleId());
    };
    if (bootstrap_empty_chain && !audit_checkpoint) {
        // Chainstate-only reindex preserves the fully validated block index
        // and durable finality, but reconstructs coins from an empty chain.
        // The real genesis record must remain activatable in that state.
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(!node::fReindex.load());
            genesis = chainman.m_blockman.LookupBlockIndex(consensus.hashGenesisBlock);
            BOOST_REQUIRE(genesis != nullptr);
            BOOST_REQUIRE(durable_target->IsValid(provisional_winner ?
                BLOCK_VALID_TRANSACTIONS : BLOCK_VALID_SCRIPTS));
            BOOST_REQUIRE(durable_target->GetAncestor(0) == genesis);
            bootstrap_competitor[0] = add_index(*durable_ancestor);
            bootstrap_competitor[1] = add_index(*bootstrap_competitor[0]);
            BOOST_REQUIRE(bootstrap_competitor.back()->nChainWork > durable_target->nChainWork);
            chainman.ResetChainstates();
            auto& rebuilt{chainman.InitializeChainstate(node_context.mempool.get())};
            rebuilt.InitCoinsDB(1U << 20, /*in_memory=*/true, /*should_wipe=*/true);
            rebuilt.InitCoinsCache(1U << 20);
            BOOST_REQUIRE(chainman.ActiveTip() == nullptr);
            BOOST_REQUIRE(rebuilt.CoinsTip().GetBestBlock().IsNull());
            BOOST_REQUIRE(rebuilt.CoinsDB().GetBestBlock().IsNull());
            BOOST_REQUIRE(rebuilt.CoinsDB().GetHeadBlocks().empty());
            BOOST_REQUIRE(!rebuilt.CoinsDB().Cursor()->Valid());
            // The retained index selects higher work normally. Bootstrap must
            // select genesis without trusting or reading this conflicting body.
            for (CBlockIndex* index : chainman.m_blockman.GetAllBlockIndices()) {
                if (provisional_winner && index->nHeight != 0) {
                    // A completed full scan knows transaction-valid bodies,
                    // but has not reconstructed their chainstate or undo yet.
                    index->nStatus = (index->nStatus & ~(BLOCK_VALID_MASK | BLOCK_HAVE_UNDO)) |
                                     BLOCK_VALID_TRANSACTIONS;
                    index->nUndoPos = 0;
                }
                if (index->IsValid(BLOCK_VALID_TRANSACTIONS) && index->HaveNumChainTxs() &&
                    !(index->nStatus & BLOCK_CONFLICT_CHAINLOCK)) {
                    rebuilt.setBlockIndexCandidates.insert(index);
                }
            }

            // Mirror startup's effective_reindex_geth auxiliary reset before
            // recreating LLMQ. In particular, the old DMN manager must not
            // retain its height-100 tip while coins restart from genesis.
            const auto auxiliary_params = [&](const char* name) {
                return DBParams{
                    .path = chainman.m_options.datadir / name,
                    .cache_bytes = 1U << 20,
                    .memory_only = true,
                    .wipe_data = true};
            };
            deterministicMNManager.reset();
            deterministicMNManager = std::make_unique<CDeterministicMNManager>(
                auxiliary_params("evodb_dmn"));
            governance.reset();
            governance = std::make_unique<CGovernanceManager>(chainman);
            sporkManager.reset();
            sporkManager = std::make_unique<CSporkManager>();
            netfulfilledman.reset();
            netfulfilledman = std::make_unique<CNetFulfilledRequestManager>();
            mmetaman.reset();
            mmetaman = std::make_unique<CMasternodeMetaMan>();
            pnevmtxrootsdb.reset();
            pnevmtxrootsdb = std::make_unique<CNEVMTxRootsDB>(
                auxiliary_params("nevmtxroots"));
            pnevmtxmintdb.reset();
            pnevmtxmintdb = std::make_unique<CNEVMMintedTxDB>(
                auxiliary_params("nevmminttx"));
            pblockindexdb.reset();
            pblockindexdb = std::make_unique<CBlockIndexDB>(
                auxiliary_params("dbblockindex"));
            pnevmdatadb.reset();
            pnevmdatadb = std::make_unique<CNEVMDataDB>(
                auxiliary_params("nevmdata"));
            // Durable finality and PoDA blob data survive this rebuild.
        }
    }
    if (!audit_checkpoint) {
        LOCK(::cs_main);
        llmq::InitLLMQSystem(*Assert(node_context.connman),
                             *Assert(node_context.peerman), chainman);
        BOOST_CHECK(chainman.GetPQHistoryAuthState() ==
                    PQHistoryAuthState::PENDING);
    }
    BOOST_REQUIRE(llmq::chainLocksHandler != nullptr);
    BOOST_CHECK(!llmq::chainLocksHandler->GetBestChainLock());
    if (audit_checkpoint) {
        const auto identity{llmq::chainLocksHandler->GetDurableFinalityTargetForStartup()};
        BOOST_REQUIRE(identity);
        BOOST_CHECK_EQUAL(identity->height, winner.statement.height);
        BOOST_CHECK(identity->block_hash == winner.statement.block_hash);
        const auto lookup{llmq::chainLocksHandler->GetRecoveryUniversePersistenceLookup()};
        BOOST_REQUIRE(lookup);
        const auto retained_universe{lookup(recovery_universe->SourceId())};
        BOOST_REQUIRE(retained_universe);
        BOOST_CHECK(retained_universe->CapsuleId() == recovery_universe->CapsuleId());
        if (preserve_audit_checkpoint || persisted_full_reindex) {
            check_audit_stores();
            return;
        }
    }

    struct ResetInterrupt {
        util::SignalInterrupt& interrupt;
        ~ResetInterrupt() { interrupt.reset(); }
    };
    const auto check_default_callers_fail_closed = [&] {
        auto& chainstate{chainman.ActiveChainstate()};
        const CBlockIndex* original_tip;
        uint256 original_coins;
        uint32_t original_status;
        std::size_t original_candidate_count;
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(!node::fReindex.load());
            BOOST_REQUIRE(!durable_target->IsValid(BLOCK_VALID_SCRIPTS));
            original_tip = chainman.ActiveTip();
            BOOST_REQUIRE(original_tip != nullptr);
            original_coins = chainstate.CoinsTip().GetBestBlock();
            original_status = durable_target->nStatus;
            original_candidate_count = chainstate.setBlockIndexCandidates.size();
            const CBlockIndex* floor{nullptr};
            const CBlockIndex* target{nullptr};
            std::string error;
            BOOST_REQUIRE(!llmq::chainLocksHandler->GetDurableFinalityRecoveryFloor(
                floor, target, error));
            BOOST_CHECK(floor == nullptr);
            BOOST_CHECK(target == nullptr);
            BOOST_CHECK(error.find("not fully validated") != std::string::npos);
            BOOST_REQUIRE(!chainman.CheckPQActivationHandoffDisconnect(*original_tip, error));
            BOOST_CHECK(error.find("not fully validated") != std::string::npos);
        }
        BlockValidationState invalidation_state;
        BOOST_REQUIRE(!chainstate.InvalidateBlock(invalidation_state, durable_target,
            /*bReverify=*/false, /*bUpdateSpecialTxState=*/true));
        BOOST_CHECK(invalidation_state.IsError());
        BOOST_CHECK(invalidation_state.GetRejectReason().find("not fully validated") != std::string::npos);
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == original_tip);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == original_coins);
        BOOST_CHECK(durable_target->nStatus == original_status);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.size(), original_candidate_count);
    };

    if (scenario == DurableSideBranchCase::DIVERGENT_PROVISIONAL) {
        check_default_callers_fail_closed();
        auto& chainstate{chainman.ActiveChainstate()};
        const uint256 original_coins{WITH_LOCK(
            ::cs_main, return chainstate.CoinsTip().GetBestBlock())};
        const uint32_t original_status{WITH_LOCK(
            ::cs_main, return durable_target->nStatus)};
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(chainstate.m_chain.FindFork(durable_target) == active_lca);
            BOOST_REQUIRE(active_lca != active_tip);
            chainstate.setBlockIndexCandidates.clear();
            for (CBlockIndex* index : chainman.m_blockman.GetAllBlockIndices()) {
                if (index->IsValid(BLOCK_VALID_TRANSACTIONS) && index->HaveNumChainTxs() &&
                    !(index->nStatus & BLOCK_CONFLICT_CHAINLOCK) &&
                    !node::CBlockIndexWorkComparator()(index, active_tip)) {
                    chainstate.setBlockIndexCandidates.insert(index);
                }
            }
            BOOST_REQUIRE(!chainstate.setBlockIndexCandidates.empty());
            BOOST_REQUIRE(*chainstate.setBlockIndexCandidates.rbegin() == durable_target);
            chainstate.ResetChainLockConflictMarkingStatsForTesting();
        }
        BOOST_REQUIRE(!chainman.m_interrupt);
        BOOST_REQUIRE_EQUAL(node_context.exit_status.load(), EXIT_SUCCESS);
        BlockValidationState state;
        BOOST_REQUIRE(!chainstate.ActivateBestChain(state));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
            "provisional durable finality permits only forward activation");
        BOOST_CHECK(!chainman.m_interrupt);
        BOOST_CHECK_EQUAL(node_context.exit_status.load(), EXIT_SUCCESS);
        LOCK(::cs_main);
        BOOST_CHECK(chainman.ActiveTip() == active_tip);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == original_coins);
        BOOST_CHECK(durable_target->nStatus == original_status);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(durable_target), 1U);
        for (const CBlockIndex* index{active_tip}; index != nullptr; index = index->pprev) {
            BOOST_CHECK_EQUAL(index->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        }
        for (const CBlockIndex* index{durable_target}; index != nullptr; index = index->pprev) {
            BOOST_CHECK_EQUAL(index->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
        }
        const auto stats{chainstate.GetChainLockConflictMarkingStatsForTesting()};
        BOOST_CHECK_EQUAL(stats.batch_calls, 0U);
        BOOST_CHECK_EQUAL(stats.disconnect_tip_calls, 0U);
        BOOST_CHECK_EQUAL(stats.tip_publications, 0U);
        return;
    }

    if (bootstrap_empty_chain) {
        struct RestoreMasternodeSync {
            int mode{masternodeSync.GetAssetID()};
            ~RestoreMasternodeSync() { masternodeSync.SetSyncMode(mode); }
        } restore_sync;
        masternodeSync.SetSyncMode(MASTERNODE_SYNC_GOVERNANCE);
        const auto check_winner_preserved = [&] {
            const auto identity{llmq::chainLocksHandler->GetDurableFinalityTargetForStartup()};
            BOOST_REQUIRE(identity.has_value());
            BOOST_CHECK_EQUAL(identity->height, winner.statement.height);
            BOOST_CHECK(identity->block_hash == winner.statement.block_hash);
            BOOST_CHECK(!llmq::chainLocksHandler->GetBestChainLock());
            LOCK(::cs_main);
            BOOST_CHECK(chainman.GetPQHistoryAuthState() == PQHistoryAuthState::PENDING);
            for (const CBlockIndex* index{durable_target}; index != nullptr; index = index->pprev) {
                BOOST_CHECK_EQUAL(index->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
            }
        };
        check_winner_preserved();
        auto& rebuilt{chainman.ActiveChainstate()};
        if (provisional_winner) {
            // The initial import may activate genesis while its full-reindex
            // authority is still live. Later peer repair runs after scan completion.
            BOOST_REQUIRE(!node::fReindex.load());
            node::fReindex = true;
        }
        {
            bool genesis_notified{false};
            ResetInterrupt reset_interrupt{node_context.kernel->interrupt};
            const boost::signals2::scoped_connection genesis_notification{
                uiInterface.NotifyBlockTip_connect(
                    [&](SynchronizationState, const CBlockIndex* tip) {
                        genesis_notified = tip == genesis;
                        node_context.kernel->interrupt();
                    })};
            BlockValidationState bootstrap_state;
            BOOST_REQUIRE_MESSAGE(rebuilt.ActivateBestChain(bootstrap_state), bootstrap_state.ToString());
            BOOST_CHECK(bootstrap_state.IsValid());
            BOOST_CHECK(genesis_notified);
            BOOST_CHECK(chainman.m_interrupt);
        }
        BOOST_CHECK(!chainman.m_interrupt);
        if (provisional_winner) {
            BOOST_REQUIRE(node::fReindex.load());
            node::fReindex = false;
            check_default_callers_fail_closed();
        }
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(chainman.ActiveTip() == genesis);
            BOOST_CHECK(rebuilt.CoinsTip().GetBestBlock() == genesis->GetBlockHash());
            BOOST_REQUIRE_EQUAL(rebuilt.setBlockIndexCandidates.count(bootstrap_competitor.back()), 1U);
            BOOST_CHECK_EQUAL(bootstrap_competitor.back()->nStatus & (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK), 0U);
            // With genesis established, ordinary preflight must reject the
            // same incompatible candidate before reading its synthetic body.
            rebuilt.ResetChainLockConflictMarkingStatsForTesting();
        }
        const CBlockIndex* first_replayed_index{WITH_LOCK(
            ::cs_main, return durable_target->GetAncestor(1))};
        BOOST_REQUIRE(first_replayed_index != nullptr);
        BOOST_REQUIRE(active_lca->nHeight < consensus.DIP0003Height);
        CBlock first_replayed_block;
        BOOST_REQUIRE(chainman.m_blockman.ReadBlockFromDisk(
            first_replayed_block, *first_replayed_index));
        BOOST_REQUIRE(first_replayed_block.GetHash() == first_replayed_index->GetBlockHash());
        BOOST_REQUIRE(!first_replayed_block.vtx.empty());
        BOOST_REQUIRE(first_replayed_block.vtx.front()->IsCoinBase());
        BOOST_REQUIRE(!first_replayed_block.vtx.front()->vout.empty());
        const COutPoint replayed_coinbase{
            first_replayed_block.vtx.front()->GetHash(), 0};
        const CTxOut expected_coinbase{first_replayed_block.vtx.front()->vout.front()};
        BOOST_REQUIRE(!expected_coinbase.scriptPubKey.IsUnspendable());
        BOOST_REQUIRE(!WITH_LOCK(::cs_main, return rebuilt.CoinsTip().HaveCoin(replayed_coinbase)));
        const CBlockIndex* progressed_tip{nullptr};
        {
            // The same invocation must retire the incompatible candidate and
            // begin replaying the winner's real indexed ancestry. Stop at the
            // first connected tip, before its synthetic suffix above height 90.
            ResetInterrupt reset_interrupt{node_context.kernel->interrupt};
            const boost::signals2::scoped_connection progress_notification{
                uiInterface.NotifyBlockTip_connect(
                    [&](SynchronizationState, const CBlockIndex* tip) {
                        if (tip != nullptr && tip->nHeight > 0) {
                            progressed_tip = tip;
                            node_context.kernel->interrupt();
                        }
                    })};
            BlockValidationState competing_state;
            BOOST_REQUIRE_MESSAGE(rebuilt.ActivateBestChain(competing_state), competing_state.ToString());
            BOOST_CHECK(competing_state.IsValid());
            BOOST_REQUIRE_MESSAGE(progressed_tip != nullptr,
                "conflict rejection did not resume compatible indexed replay in the same activation call");
            BOOST_CHECK(chainman.m_interrupt);
        }
        BOOST_CHECK(!chainman.m_interrupt);
        check_winner_preserved();
        {
            LOCK(::cs_main);
            BOOST_REQUIRE(chainman.ActiveTip() == progressed_tip);
            BOOST_REQUIRE(progressed_tip->nHeight > 0);
            BOOST_REQUIRE(progressed_tip->nHeight <= active_lca->nHeight);
            BOOST_CHECK(durable_target->GetAncestor(progressed_tip->nHeight) == progressed_tip);
            BOOST_CHECK(rebuilt.CoinsTip().GetBestBlock() == progressed_tip->GetBlockHash());
            Coin recovered_coin;
            BOOST_REQUIRE(rebuilt.CoinsTip().GetCoin(replayed_coinbase, recovered_coin));
            BOOST_CHECK(recovered_coin.out == expected_coinbase);
            BOOST_CHECK_EQUAL(recovered_coin.nHeight, first_replayed_index->nHeight);
            BOOST_CHECK(recovered_coin.IsCoinBase());
            const CBlockIndex* floor{nullptr};
            const CBlockIndex* target{nullptr};
            std::string error;
            if (provisional_winner) {
                // Forward replay does not grant the ordinary disconnect/invalidate
                // callers a provisional finality floor.
                BOOST_REQUIRE(!llmq::chainLocksHandler->GetDurableFinalityRecoveryFloor(
                    floor, target, error));
                BOOST_CHECK(floor == nullptr);
                BOOST_CHECK(target == nullptr);
                BOOST_CHECK(!durable_target->IsValid(BLOCK_VALID_SCRIPTS));
            } else {
                BOOST_REQUIRE_MESSAGE(llmq::chainLocksHandler->GetDurableFinalityRecoveryFloor(
                    floor, target, error), error);
                BOOST_CHECK(floor == progressed_tip);
                BOOST_CHECK(target == durable_target);
            }
            for (const CBlockIndex* index : bootstrap_competitor) {
                BOOST_CHECK(index->nStatus & BLOCK_CONFLICT_CHAINLOCK);
                BOOST_CHECK_EQUAL(index->nStatus & BLOCK_FAILED_MASK, 0U);
            }
            BOOST_CHECK_EQUAL(rebuilt.setBlockIndexCandidates.count(bootstrap_competitor.back()), 0U);
            BOOST_CHECK_EQUAL(rebuilt.setBlockIndexCandidates.count(durable_target), 1U);
            const auto stats{rebuilt.GetChainLockConflictMarkingStatsForTesting()};
            BOOST_CHECK_EQUAL(stats.batch_calls, 1U);
            BOOST_CHECK_EQUAL(stats.disconnect_tip_calls, 0U);
            BOOST_CHECK_EQUAL(stats.tip_publications, 0U);
            BOOST_CHECK(!node::fReindex.load());
        }
        if (audit_checkpoint) check_audit_stores();
        return;
    }

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

    auto& chainstate{chainman.ActiveChainstate()};
    const uint256 original_coins_tip{
        WITH_LOCK(::cs_main, return chainstate.CoinsTip().GetBestBlock())};
    const auto original_candidates{
        WITH_LOCK(::cs_main, return chainstate.setBlockIndexCandidates)};
    struct RestoreCandidates {
        Chainstate& chainstate;
        const std::set<CBlockIndex*, node::CBlockIndexWorkComparator> candidates;
        ~RestoreCandidates()
        {
            LOCK(::cs_main);
            chainstate.setBlockIndexCandidates = candidates;
        }
    } restore_candidates{chainstate, original_candidates};

    CBlockIndex* durable_child{nullptr};
    {
        LOCK(::cs_main);
        durable_child = add_index(*durable_target);
    }
    const auto check_preflight =
        [&](const std::vector<CBlockIndex*>& conflicting) {
        BOOST_REQUIRE(!conflicting.empty());
        {
            LOCK(::cs_main);
            // Only the incompatible tip is initially eligible. Preset the
            // interrupt so ABC stops after its guaranteed first step; restored
            // synthetic candidates are inspected without being connected.
            chainstate.setBlockIndexCandidates.clear();
            chainstate.setBlockIndexCandidates.insert(active_tip);
            chainstate.setBlockIndexCandidates.insert(conflicting.back());
            chainstate.ResetChainLockConflictMarkingStatsForTesting();
        }
        BlockValidationState state;
        {
            BOOST_REQUIRE(!chainman.m_interrupt);
            ResetInterrupt reset_interrupt{node_context.kernel->interrupt};
            node_context.kernel->interrupt();
            BOOST_REQUIRE_MESSAGE(chainstate.ActivateBestChain(state),
                                  state.ToString());
        }
        BOOST_CHECK(!chainman.m_interrupt);
        BOOST_CHECK(state.IsValid());
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman.ActiveTip(), active_tip);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == original_coins_tip);
        for (CBlockIndex* index : conflicting) {
            BOOST_CHECK(index->nStatus & BLOCK_CONFLICT_CHAINLOCK);
            BOOST_CHECK(!(index->nStatus & BLOCK_FAILED_MASK));
            BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(index), 0U);
        }
        // Preserve the winner, its descendant, and every shared ancestor, not
        // merely the currently active fork point.
        bool durable_ancestry_preserved{true};
        for (const CBlockIndex* index{durable_child};
             index != active_lca->pprev; index = index->pprev) {
            durable_ancestry_preserved = durable_ancestry_preserved &&
                !(index->nStatus &
                  (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK));
        }
        BOOST_CHECK(durable_ancestry_preserved);
        for (const CBlockIndex* index{active_tip};
             index != active_lca; index = index->pprev) {
            BOOST_CHECK(!(index->nStatus &
                          (BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK)));
        }
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(durable_target), 1U);
        BOOST_CHECK_EQUAL(chainstate.setBlockIndexCandidates.count(durable_child), 1U);
        const auto stats{chainstate.GetChainLockConflictMarkingStatsForTesting()};
        BOOST_CHECK_EQUAL(stats.batch_calls, 1U);
        BOOST_CHECK_EQUAL(stats.input_roots, 1U);
        BOOST_CHECK_EQUAL(stats.visited_blocks, conflicting.size());
        BOOST_CHECK_EQUAL(stats.disconnect_tip_calls, 0U);
        BOOST_CHECK_EQUAL(stats.tip_publications, 0U);
    };

    // The candidate and durable winner share a long inactive prefix. The
    // first conflicting child is after their own common ancestor, not after
    // the much earlier fork with the active chain.
    std::vector<CBlockIndex*> shared_prefix_competitor;
    {
        LOCK(::cs_main);
        CBlockIndex* parent{durable_ancestor};
        for (int count{0}; count < 3; ++count) {
            parent = add_index(*parent);
            shared_prefix_competitor.push_back(parent);
        }
        BOOST_REQUIRE_EQUAL(
            LastCommonAncestor(shared_prefix_competitor.back(), durable_target),
            durable_ancestor);
        BOOST_REQUIRE_EQUAL(
            chainstate.m_chain.FindFork(shared_prefix_competitor.back()), active_lca);
    }
    check_preflight(shared_prefix_competitor);

    // Conversely, the candidate/winner fork precedes an active competing
    // suffix. Preflight must retire only the new inactive extension and leave
    // disconnection of the active suffix to normal finality enforcement.
    std::vector<CBlockIndex*> active_extension;
    {
        LOCK(::cs_main);
        active_extension.push_back(add_index(*active_tip));
        active_extension.push_back(add_index(*active_extension.back()));
        BOOST_REQUIRE_EQUAL(
            LastCommonAncestor(active_extension.back(), durable_target), active_lca);
        BOOST_REQUIRE_EQUAL(
            chainstate.m_chain.FindFork(active_extension.back()), active_tip);
    }
    check_preflight(active_extension);
}
BOOST_FIXTURE_TEST_CASE(
    invalidate_rejects_preimport_durable_side_branch_boundary,
    TestChain100Setup)
{
    CheckPreimportDurableSideBranchBoundary(m_node, DurableSideBranchCase::ACTIVE_VALIDATED);
}

BOOST_FIXTURE_TEST_CASE(
    chainstate_rebuild_bootstraps_genesis_with_retained_durable_winner,
    TestChain100Setup)
{
    CheckPreimportDurableSideBranchBoundary(m_node, DurableSideBranchCase::BOOTSTRAP_VALIDATED);
}

BOOST_FIXTURE_TEST_CASE(
    activation_replays_provisional_durable_winner_after_reindex_scan,
    TestChain100Setup)
{
    CheckPreimportDurableSideBranchBoundary(m_node, DurableSideBranchCase::FINISHED_REINDEX_PROVISIONAL);
}

BOOST_FIXTURE_TEST_CASE(
    activation_refuses_provisional_winner_reorganization,
    TestChain100Setup)
{
    CheckPreimportDurableSideBranchBoundary(m_node, DurableSideBranchCase::DIVERGENT_PROVISIONAL);
}

struct AuditCheckpointStartupSetup : TestChain100Setup {
    AuditCheckpointStartupSetup()
        : TestChain100Setup{ChainType::REGTEST, {}, COINBASE_MATURITY,
                            /*coins_db_in_memory=*/false,
                            /*block_tree_db_in_memory=*/false}
    {
    }
};

BOOST_FIXTURE_TEST_CASE(
    chainstate_rebuild_resets_audit_checkpoint_and_replays,
    AuditCheckpointStartupSetup)
{
    CheckPreimportDurableSideBranchBoundary(m_node,
        DurableSideBranchCase::AUDIT_CHECKPOINT_REBUILD, &m_cache_sizes);
}

BOOST_FIXTURE_TEST_CASE(
    geth_only_rebuild_preserves_audit_checkpoint_and_staging,
    AuditCheckpointStartupSetup)
{
    CheckPreimportDurableSideBranchBoundary(m_node,
        DurableSideBranchCase::AUDIT_CHECKPOINT_GETH_ONLY, &m_cache_sizes);
}

BOOST_FIXTURE_TEST_CASE(
    geth_rebuild_with_empty_coins_resets_audit_checkpoint_and_replays,
    AuditCheckpointStartupSetup)
{
    CheckPreimportDurableSideBranchBoundary(m_node,
        DurableSideBranchCase::AUDIT_CHECKPOINT_EMPTY_GETH, &m_cache_sizes);
}

BOOST_FIXTURE_TEST_CASE(
    persisted_full_reindex_resets_audit_checkpoint_and_staging,
    AuditCheckpointStartupSetup)
{
    CheckPreimportDurableSideBranchBoundary(m_node,
        DurableSideBranchCase::AUDIT_CHECKPOINT_FULL_REINDEX, &m_cache_sizes);
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
