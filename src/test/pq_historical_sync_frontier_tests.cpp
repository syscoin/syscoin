// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>

#include <chain.h>
#include <governance/governanceclasses.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>

#include <functional>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace llmq::test {

class HistoricalSyncFrontierTestAccess {
public:
    using Frontier = CChainLocksHandler::LiveSigningValidationFrontier;

    static bool HistoricalBaseAheadOfDurableWinner(
        const pq::FinalChainLockRecordMetadata* current,
        const pq::FinalChainLockRecordMetadata& historical_base)
    {
        return CChainLocksHandler::IsHistoricalAuthorizationBaseAheadOfDurableWinner(
            current, historical_base);
    }

    static bool RetentionMutationReady(
        const pq::FinalChainLockRecordMetadata* accepted,
        const pq::FinalChainLockRecordMetadata* durable, const CChain& chain)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return CChainLocksHandler::IsHistoricalSyncRetentionMutationReady(accepted, durable, chain);
    }

    static bool Advance(
        Frontier& frontier, const CChain& chain, const CBlockIndex& target,
        const pq::ChainLockPredecessor& prior,
        const pq::ChainLockFinalityStoreConfig& config, const uint256& genesis,
        uint64_t revision, const pq::HistoricalSyncBoundary* coverage,
        const std::function<bool(const pq::BTCCReceipt&)>& check,
        uint64_t& examined, std::size_t budget = 4096)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        const auto status = [&](const pq::BTCCReceipt& receipt, const CBlockIndex&) {
            return check(receipt)
                ? CChainLocksHandler::BTCCReceiptCertificateStatus::VERIFIED
                : CChainLocksHandler::BTCCReceiptCertificateStatus::MISSING;
        };
        return CChainLocksHandler::AdvanceLiveSigningValidationFrontier(
            frontier, chain, target, prior, config, genesis, revision,
            status, examined, budget, coverage);
    }

    static bool ExtendForGovernance(
        const pq::HistoricalSyncBoundary& established,
        const pq::HistoricalSyncBoundary& selected, const Frontier& frontier,
        const CChain& chain, uint64_t revision, const uint256& genesis,
        const pq::ChainLockFinalityStoreConfig& config)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return CChainLocksHandler::ShouldExtendPoWHistoricalCoverageForGovernance(
            established, selected, frontier, chain, revision, genesis, config);
    }
};

} // namespace llmq::test

namespace {

using Access = llmq::test::HistoricalSyncFrontierTestAccess;
using namespace llmq::pq;

uint256 TestHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<unsigned char>(value >> (8 * i));
    }
    return hash;
}

struct History {
    ChainLockFinalityStoreConfig config;
    uint256 genesis{TestHash(1)};
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks;
    CChain chain;
    BTCCReceiptState receipt_state;
    HistoricalSyncBoundary coverage;
    ChainLockPredecessor prior;

    explicit History(std::size_t count = 926)
        : hashes(count), blocks(count)
    {
        config.chainlock_schedule = *MakeChainLockScheduleConfig(0);
        config.btcc_schedule.candidate_origin = 865;
        config.activation_predecessor_height = 864;
        BOOST_REQUIRE(config.IsValid());
        for (std::size_t i{0}; i < count; ++i) {
            hashes[i] = TestHash(10'000 + i);
            auto& block{blocks[i]};
            block.nHeight = static_cast<int32_t>(i);
            block.phashBlock = &hashes[i];
            block.pprev = i == 0 ? nullptr : &blocks[i - 1];
            block.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                BLOCK_PQ_BTCC_INDEX_VALIDATED | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
                BLOCK_GOVERNANCE_VALIDATED;
            block.pqPaymentProbationStateHash = TestHash(2);
            block.BuildSkip();
        }
        chain.SetTip(blocks.back());
        const auto initial{AddReceipt(865, 875)};
        prior = {865, hashes[865], initial.accepted_cursor};
        coverage.durable_prior = {prior.height, prior.block_hash, TestHash(3)};
        coverage.receipt = AddReceipt(875, 885);
        coverage.carrier_height = 885;
        coverage.carrier_hash = hashes[885];
        coverage.coverage_height = 889;
        coverage.coverage_hash = hashes[889];
        coverage.receipt_state = receipt_state;
        coverage.probation_state_hash = TestHash(2);
        BOOST_REQUIRE(coverage.IsStructurallyValid());
    }

    BTCCReceipt AddReceipt(int32_t target, int32_t carrier)
    {
        blocks[target].btcpPrevCommitment = TestHash(20'000 + target);
        BTCCReceipt receipt;
        receipt.chainlock_target_height = target;
        receipt.chainlock_target_hash = hashes[target];
        receipt.chainlock_logical_id = TestHash(30'000 + target);
        receipt.accepted_cursor = {target, hashes[target], blocks[target].btcpPrevCommitment};
        const auto next{ApplyBTCCReceiptState(
            genesis, config.chainlock_schedule, config.btcc_schedule,
            config.activation_predecessor_height, carrier, hashes[carrier],
            receipt_state, receipt)};
        BOOST_REQUIRE(next);
        receipt_state = *next;
        for (std::size_t i{static_cast<std::size_t>(carrier)}; i < blocks.size(); ++i) {
            auto& block{blocks[i]};
            block.pqBTCCReceiptCursorHeight = next->cursor.sys_height;
            block.pqBTCCReceiptCursorSysHash = next->cursor.sys_hash;
            block.pqBTCCReceiptCursorBTCHash = next->cursor.btc_hash;
            block.pqBTCCReceiptStateHash = next->cumulative_hash;
            block.pqBTCCReceiptLatestTargetHeight = next->latest_chainlock_target_height;
            block.pqBTCCReceiptLatestCarrierHeight = next->latest_receipt_carrier_height;
        }
        blocks[carrier].pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
        return receipt;
    }

    bool Advance(Access::Frontier& frontier, uint64_t& examined,
                 const HistoricalSyncBoundary* boundary,
                 const std::function<bool(const BTCCReceipt&)>& check,
                 int32_t target = 900, uint64_t revision = 1,
                 std::size_t budget = 4096)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        return Access::Advance(frontier, chain, blocks[target], prior, config,
                               genesis, revision, boundary, check, examined, budget);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_historical_sync_frontier_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(historical_authorization_exception_ends_after_durable_successor)
{
    FinalChainLockRecordMetadata historical_base;
    historical_base.statement.height = 875;
    FinalChainLockRecordMetadata current;
    current.statement.height = 865;
    BOOST_CHECK(Access::HistoricalBaseAheadOfDurableWinner(nullptr, historical_base));
    BOOST_CHECK(Access::HistoricalBaseAheadOfDurableWinner(&current, historical_base));
    current.statement.height = historical_base.statement.height;
    BOOST_CHECK(!Access::HistoricalBaseAheadOfDurableWinner(&current, historical_base));
    // B stays available for prefix/restart coverage, but later candidates must
    // converge with the now durable C, including its intervening roster edge.
    current.statement.height = 900;
    BOOST_CHECK(!Access::HistoricalBaseAheadOfDurableWinner(&current, historical_base));
}

BOOST_AUTO_TEST_CASE(pending_or_offbranch_durable_winner_preserves_historical_dependencies)
{
    History history;
    FinalChainLockRecordMetadata durable;
    durable.logical_id = TestHash(40'000);
    durable.witness_id = TestHash(40'001);
    durable.statement.height = 900;
    durable.statement.block_hash = history.hashes[900];
    auto accepted{durable};
    LOCK(cs_main);
    BOOST_CHECK(Access::RetentionMutationReady(nullptr, nullptr, history.chain));
    BOOST_CHECK(!Access::RetentionMutationReady(nullptr, &durable, history.chain));
    BOOST_CHECK(!Access::RetentionMutationReady(&accepted, nullptr, history.chain));
    BOOST_CHECK(Access::RetentionMutationReady(&accepted, &durable, history.chain));
    accepted.logical_id = TestHash(40'002);
    BOOST_CHECK(!Access::RetentionMutationReady(&accepted, &durable, history.chain));
    accepted = durable;
    accepted.statement.block_hash = TestHash(40'003);
    BOOST_CHECK(!Access::RetentionMutationReady(&accepted, &accepted, history.chain));
    history.chain.SetTip(history.blocks[899]);
    BOOST_CHECK(!Access::RetentionMutationReady(&durable, &durable, history.chain));
    history.chain.SetTip(history.blocks.back());
    BOOST_CHECK(Access::RetentionMutationReady(&durable, &durable, history.chain));
    history.blocks[900].nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!Access::RetentionMutationReady(&durable, &durable, history.chain));
}

BOOST_AUTO_TEST_CASE(covered_history_resumes_without_a_newer_certificate)
{
    History history;
    Access::Frontier frontier;
    uint64_t examined{0};
    unsigned int certificate_checks{0};
    const auto unavailable = [&](const BTCCReceipt&) {
        ++certificate_checks;
        return false;
    };
    LOCK(cs_main);
    std::vector<uint32_t> original_status;
    for (const auto& block : history.blocks) original_status.push_back(block.nStatus);
    const auto actual_finality{history.prior};

    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage, unavailable));
    BOOST_CHECK_EQUAL(certificate_checks, 0U);
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 900);
    BOOST_CHECK(frontier.durable_predecessor == actual_finality);
    BOOST_CHECK_EQUAL(examined, 35U);
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage, unavailable, 905));
    BOOST_CHECK_EQUAL(examined, 40U);
    BOOST_CHECK_EQUAL(certificate_checks, 0U);
    for (std::size_t i{0}; i < original_status.size(); ++i) {
        BOOST_CHECK_EQUAL(history.blocks[i].nStatus, original_status[i]);
    }
}

BOOST_AUTO_TEST_CASE(live_suffix_still_requires_its_exact_certificate)
{
    History history;
    const auto live{history.AddReceipt(885, 895)};
    Access::Frontier frontier;
    uint64_t examined{0};
    uint256 requested;
    const auto unavailable = [&](const BTCCReceipt& receipt) {
        requested = receipt.chainlock_logical_id;
        return false;
    };
    LOCK(cs_main);
    BOOST_CHECK(!history.Advance(frontier, examined, &history.coverage, unavailable));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 894);
    BOOST_CHECK(requested == live.chainlock_logical_id);
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage,
        [&](const BTCCReceipt& receipt) { return receipt == live; }));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 900);
}

BOOST_AUTO_TEST_CASE(fresh_history_keeps_the_activation_floor_without_inventing_finality)
{
    History history;
    history.prior = {history.config.activation_predecessor_height,
                     history.hashes[history.config.activation_predecessor_height], {}};
    history.coverage.durable_prior = {};
    Access::Frontier frontier;
    uint64_t examined{0};
    LOCK(cs_main);
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage,
                                   [](const auto&) { return false; }));
    BOOST_CHECK(frontier.durable_predecessor == history.prior);
    BOOST_CHECK_EQUAL(frontier.durable_predecessor.height, 864);
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 900);
}

BOOST_AUTO_TEST_CASE(boundary_must_match_branch_prior_and_reconstructed_state)
{
    History history;
    const std::vector<std::function<void(HistoricalSyncBoundary&)>> corruptions{
        [](auto& boundary) { boundary.coverage_hash = TestHash(40'001); },
        [](auto& boundary) { boundary.carrier_hash = TestHash(40'002); },
        [](auto& boundary) { boundary.durable_prior.block_hash = TestHash(40'003); },
        [](auto& boundary) { --boundary.durable_prior.height; },
        [](auto& boundary) { boundary.receipt_state.cumulative_hash = TestHash(40'004); },
        [](auto& boundary) { boundary.payment_audit_state.cumulative_hash = TestHash(40'005); },
        [](auto& boundary) { boundary.probation_state_hash = TestHash(40'006); },
        [](auto& boundary) { boundary.receipt.chainlock_logical_id = TestHash(40'007); },
        [&](auto& boundary) {
            boundary.coverage_height = 900;
            boundary.coverage_hash = history.hashes[900];
        },
        [](auto& boundary) { boundary.coverage_height = 901; },
        [](auto& boundary) { boundary.durable_prior = {}; },
    };
    LOCK(cs_main);
    for (const auto& corrupt : corruptions) {
        Access::Frontier frontier;
        uint64_t examined{0};
        auto boundary{history.coverage};
        corrupt(boundary);
        BOOST_CHECK(!history.Advance(frontier, examined, &boundary,
                                      [](const auto&) { return true; }));
        BOOST_CHECK(!frontier.initialized);
        BOOST_CHECK_EQUAL(examined, 0U);
    }
}

BOOST_AUTO_TEST_CASE(capability_removal_or_change_revokes_cached_history)
{
    History history;
    Access::Frontier frontier;
    uint64_t examined{0};
    const auto unavailable = [](const BTCCReceipt&) { return false; };
    LOCK(cs_main);
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage, unavailable));
    BOOST_CHECK(!history.Advance(frontier, examined, nullptr, unavailable));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 874);
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage, unavailable));

    auto changed{history.coverage};
    changed.coverage_height = 890;
    changed.coverage_hash = history.hashes[890];
    const auto before{examined};
    BOOST_REQUIRE(history.Advance(frontier, examined, &changed, unavailable));
    BOOST_CHECK_EQUAL(examined, before + 35);

    history.blocks[870].nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
    BOOST_CHECK(!history.Advance(frontier, examined, &changed, unavailable, 900, 2));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, 869);
    history.hashes[885] = TestHash(50'000);
    BOOST_CHECK(!history.Advance(frontier, examined, &changed, unavailable, 900, 2));
    BOOST_CHECK(!frontier.initialized);
}

BOOST_AUTO_TEST_CASE(historical_coverage_preserves_block_provenance_and_budget)
{
    History history;
    const std::vector<std::function<uint32_t(uint32_t)>> corruptions{
        [](uint32_t status) { return status & ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED; },
        [](uint32_t status) { return status | BLOCK_ASSUMED_VALID; },
        [](uint32_t status) { return status | BLOCK_FAILED_VALID; },
        [](uint32_t status) { return (status & ~BLOCK_VALID_MASK) | BLOCK_VALID_CHAIN; },
    };
    LOCK(cs_main);
    for (const auto& corrupt : corruptions) {
        Access::Frontier frontier;
        uint64_t examined{0};
        const auto status{history.blocks[870].nStatus};
        history.blocks[870].nStatus = corrupt(status);
        BOOST_CHECK(!history.Advance(frontier, examined, &history.coverage,
                                      [](const auto&) { return false; }));
        BOOST_CHECK_EQUAL(frontier.validated_through_height, 869);
        history.blocks[870].nStatus = status;
    }
    Access::Frontier frontier;
    uint64_t examined{0};
    bool ready{false};
    while (!ready) {
        const auto before{examined};
        ready = history.Advance(frontier, examined, &history.coverage,
                                [](const auto&) { return false; }, 900, 1, 7);
        BOOST_CHECK_LE(examined - before, 7U);
        BOOST_REQUIRE_GT(examined, before);
    }
    BOOST_CHECK_EQUAL(examined, 35U);
}

BOOST_AUTO_TEST_CASE(pow_history_covers_deferred_governance_but_not_live_governance)
{
    int32_t superblock{890};
    while (!CSuperblock::IsValidBlockHeight(superblock)) ++superblock;
    History history{static_cast<std::size_t>(superblock + 6)};
    LOCK(cs_main);
    history.coverage.coverage_height = superblock;
    history.coverage.coverage_hash = history.hashes[superblock];
    history.blocks[superblock].nStatus &= ~BLOCK_GOVERNANCE_VALIDATED;
    Access::Frontier frontier;
    uint64_t examined{0};
    const int32_t target{superblock + 5};
    const auto budget{history.blocks.size()};
    // Historical governance data can be unavailable after ordinary IBD. The
    // explicit PoW boundary covers that obligation, not an individual check.
    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage,
                                   [](const auto&) { return false; }, target, 1, budget));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, target);
    BOOST_CHECK(!(history.blocks[superblock].nStatus & BLOCK_GOVERNANCE_VALIDATED));
    BOOST_CHECK(frontier.durable_predecessor == history.prior);

    auto shorter{history.coverage};
    shorter.coverage_height = superblock - 1;
    shorter.coverage_hash = history.hashes[superblock - 1];
    BOOST_CHECK(!history.Advance(frontier, examined, &shorter,
                                  [](const auto&) { return true; }, target, 1, budget));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, superblock - 1);

    BOOST_REQUIRE(history.Advance(frontier, examined, &history.coverage,
                                   [](const auto&) { return false; }, target, 1, budget));
    BOOST_CHECK(!history.Advance(frontier, examined, nullptr,
                                  [](const auto&) { return true; }, target, 1, budget));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, superblock - 1);
}

BOOST_AUTO_TEST_CASE(budgeted_history_scan_preserves_its_frozen_boundary)
{
    History history{5006};
    auto selected{history.coverage};
    selected.coverage_height = 4995;
    selected.coverage_hash = history.hashes[4995];
    Access::Frontier frontier;
    uint64_t examined{0};
    const auto unavailable = [](const BTCCReceipt&) { return false; };
    LOCK(cs_main);
    bool complete{false};
    while (!complete) {
        const auto before{examined};
        complete = history.Advance(frontier, examined, &history.coverage,
                                    unavailable, 5000, 1, 127);
        BOOST_CHECK_LE(examined - before, 127U);
        BOOST_REQUIRE_GT(examined, before);
        BOOST_CHECK(!Access::ExtendForGovernance(
            history.coverage, selected, frontier, history.chain, 1,
            history.genesis, history.config));
    }
    BOOST_CHECK_EQUAL(examined, 5000U - history.prior.height);
    BOOST_CHECK(frontier.historical_coverage_token ==
        GetHistoricalSyncBoundaryHash(history.genesis, history.config, history.coverage));
}

BOOST_AUTO_TEST_CASE(newly_historical_governance_obligation_permits_exact_boundary_extension)
{
    int32_t superblock{900};
    while (!CSuperblock::IsValidBlockHeight(superblock)) ++superblock;
    History history{static_cast<std::size_t>(superblock + 6)};
    LOCK(cs_main);
    history.coverage.coverage_height = superblock - 1;
    history.coverage.coverage_hash = history.hashes[superblock - 1];
    auto selected{history.coverage};
    selected.coverage_height = superblock + 1;
    selected.coverage_hash = history.hashes[superblock + 1];
    history.blocks[superblock].nStatus &=
        ~(BLOCK_GOVERNANCE_VALIDATED | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    Access::Frontier frontier;
    uint64_t examined{0};
    const auto unavailable = [](const BTCCReceipt&) { return false; };
    BOOST_CHECK(!history.Advance(frontier, examined, &history.coverage,
                                  unavailable, superblock + 5, 1, history.blocks.size()));
    BOOST_CHECK_EQUAL(frontier.validated_through_height, superblock - 1);
    const auto can_extend = [&](const HistoricalSyncBoundary& next, uint64_t revision = 1)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        return Access::ExtendForGovernance(history.coverage, next, frontier,
            history.chain, revision, history.genesis, history.config);
    };
    BOOST_CHECK(can_extend(selected));
    BOOST_CHECK(!can_extend(history.coverage));
    BOOST_CHECK(!can_extend(selected, 2));
    auto wrong_branch{selected};
    wrong_branch.coverage_hash = TestHash(80'001);
    BOOST_CHECK(!can_extend(wrong_branch));
    auto wrong_receipt{selected};
    wrong_receipt.receipt.chainlock_logical_id = TestHash(80'002);
    BOOST_CHECK(!can_extend(wrong_receipt));
    const auto status{history.blocks[superblock].nStatus};
    history.blocks[superblock].nStatus &= ~BLOCK_PQ_RECEIPT_INDEX_VALIDATED;
    BOOST_CHECK(!can_extend(selected));
    history.blocks[superblock].nStatus = status | BLOCK_ASSUMED_VALID;
    BOOST_CHECK(!can_extend(selected));
    history.blocks[superblock].nStatus = status;

    const auto actual_finality{history.prior};
    BOOST_REQUIRE(history.Advance(frontier, examined, &selected, unavailable,
                                   superblock + 5, 1, history.blocks.size()));
    BOOST_CHECK_EQUAL(history.blocks[superblock].nStatus, status);
    BOOST_CHECK(frontier.durable_predecessor == actual_finality);
    BOOST_CHECK(!Access::ExtendForGovernance(selected, selected, frontier,
        history.chain, 1, history.genesis, history.config));
}

BOOST_AUTO_TEST_SUITE_END()
