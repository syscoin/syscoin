// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/btc_header_policy.h>

#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace llmq::pq;

static_assert(!std::is_default_constructible_v<
              BTCRecoveryPrecommitRolloverProof>);
static_assert(std::is_copy_constructible_v<
              BTCRecoveryPrecommitRolloverProof>);

namespace {

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

struct Header {
    int64_t height{-1};
    int64_t confirmations{0};
    int64_t time{0};
};

struct ChainTip {
    uint256 hash;
    int64_t height{-1};
    std::string status;
};

class FakeBitcoinBackend {
public:
    bool online{true};
    bool ibd{false};
    bool wrong_header_hash{false};
    std::string chain{"regtest"};
    uint256 best_hash;
    std::map<uint256, Header> headers;
    std::map<int64_t, uint256> active_hashes;
    std::vector<ChainTip> chain_tips;
    std::map<std::string, std::size_t> method_calls;
    std::function<void(const std::vector<std::string>&, std::size_t)>
        before_call;

    bool Run(const std::vector<std::string>& args,
             UniValue& result,
             std::string& error)
    {
        const std::string method{args.empty() ? std::string{} : args.front()};
        const std::size_t method_call{++method_calls[method]};
        if (before_call) before_call(args, method_call);
        if (!online) {
            error = "backend-down";
            return false;
        }
        if (args == std::vector<std::string>{"getblockchaininfo"}) {
            result = UniValue{UniValue::VOBJ};
            result.pushKV("chain", chain);
            result.pushKV("initialblockdownload", ibd);
            result.pushKV("bestblockhash", best_hash.GetHex());
            return true;
        }
        if (args == std::vector<std::string>{"getchaintips"}) {
            result = UniValue{UniValue::VARR};
            for (const auto& tip : chain_tips) {
                UniValue value{UniValue::VOBJ};
                value.pushKV("hash", tip.hash.GetHex());
                value.pushKV("height", tip.height);
                value.pushKV("status", tip.status);
                result.push_back(std::move(value));
            }
            return true;
        }
        if (args.size() == 2 && args[0] == "getblockhash") {
            int64_t height{-1};
            if (!ParseInt64(args[1], &height)) {
                error = "bad-height";
                return false;
            }
            const auto found{active_hashes.find(height)};
            if (found == active_hashes.end()) {
                error = "height-not-found";
                return false;
            }
            result.setStr(found->second.GetHex());
            return true;
        }
        if (args.size() == 3 && args[0] == "getblockheader" &&
            args[2] == "true") {
            uint256 hash;
            hash.SetHex(args[1]);
            const auto found{headers.find(hash)};
            if (found == headers.end()) {
                error = "header-not-found";
                return false;
            }
            result = UniValue{UniValue::VOBJ};
            result.pushKV("hash", (wrong_header_hash ? NonNullHash(999999)
                                                      : hash).GetHex());
            result.pushKV("height", found->second.height);
            result.pushKV("confirmations", found->second.confirmations);
            result.pushKV("time", found->second.time);
            return true;
        }
        error = "unsupported-command";
        return false;
    }
};

struct PolicySetup {
    static constexpr int64_t NOW{2'000'000};

    FakeBitcoinBackend backend;
    BTCHeaderPolicyConfig config{
        .expected_chain = "regtest",
        .min_confirmations = 1,
        .tip_max_age = 7200,
        .max_lag_blocks = 36,
        .recent_fork_depth = 2,
    };
    uint256 tip{NonNullHash(100)};
    uint256 confirmed{NonNullHash(98)};
    uint256 previous{NonNullHash(90)};
    uint256 old{NonNullHash(60)};

    PolicySetup()
    {
        backend.best_hash = tip;
        backend.headers.emplace(tip, Header{100, 1, NOW - 30});
        backend.headers.emplace(confirmed, Header{98, 3, NOW - 90});
        backend.headers.emplace(previous, Header{90, 11, NOW - 600});
        backend.headers.emplace(old, Header{60, 41, NOW - 1200});
        backend.active_hashes.emplace(100, tip);
        backend.active_hashes.emplace(98, confirmed);
        backend.active_hashes.emplace(90, previous);
        backend.active_hashes.emplace(60, old);
        backend.chain_tips.push_back(ChainTip{tip, 100, "active"});
    }

    BTCHeaderPolicy Policy()
    {
        return BTCHeaderPolicy{
            [this](const std::vector<std::string>& args,
                   UniValue& result,
                   std::string& error) {
                return backend.Run(args, result, error);
            }};
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(btc_header_policy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(miner_selects_configured_confirmation_depth)
{
    PolicySetup setup;
    setup.config.min_confirmations = 3;
    std::string error;
    const auto selected{
        setup.Policy().SelectMiningHash(setup.config, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(selected, error);
    BOOST_CHECK(selected->btc_hash == setup.confirmed);
    BOOST_CHECK_EQUAL(selected->btc_height, 98);
    BOOST_CHECK_EQUAL(selected->confirmations, 3);
}

BOOST_AUTO_TEST_CASE(candidate_requires_exact_active_header_response)
{
    PolicySetup setup;
    std::string error;
    const auto accepted{setup.Policy().CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(accepted, error);
    BOOST_CHECK_EQUAL(accepted->btc_height, 100);

    setup.backend.wrong_header_hash = true;
    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-bestheader-invalid-response");
}

BOOST_AUTO_TEST_CASE(stale_lagging_and_wrong_network_views_fail_closed)
{
    PolicySetup setup;
    std::string error;

    setup.backend.headers[setup.tip].time =
        setup.NOW - setup.config.tip_max_age - 1;
    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.tip, std::nullopt, setup.NOW, error));
    BOOST_CHECK(error.find("btc-tip-stale") == 0);

    setup.backend.headers[setup.tip].time = setup.NOW;
    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.old, std::nullopt, setup.NOW, error));
    BOOST_CHECK(error.find("btc-candidate-too-old") == 0);

    setup.backend.chain = "main";
    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.tip, std::nullopt, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-chaininfo-wrong-chain");
}

BOOST_AUTO_TEST_CASE(backend_outage_recovers_without_persisted_state)
{
    PolicySetup setup;
    std::string error;
    setup.backend.online = false;
    BOOST_CHECK(!setup.Policy().SelectMiningHash(
        setup.config, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "backend-down");

    setup.backend.online = true;
    const auto selected{
        setup.Policy().SelectMiningHash(setup.config, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(selected, error);
    BOOST_CHECK(selected->btc_hash == setup.tip);
}

BOOST_AUTO_TEST_CASE(recent_fork_blocks_then_continuity_recovers)
{
    PolicySetup setup;
    std::string error;
    const uint256 replacement{NonNullHash(900)};
    const uint256 stale_tip{NonNullHash(901)};
    setup.backend.headers[setup.previous].confirmations = -1;
    setup.backend.active_hashes[90] = replacement;
    setup.backend.chain_tips.push_back(
        ChainTip{stale_tip, 99, "valid-fork"});

    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error));
    BOOST_CHECK(error.find("btc-recent-fork") == 0);

    setup.backend.chain_tips.back().height = 97;
    const auto recovered{setup.Policy().CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(recovered, error);
    BOOST_CHECK(recovered->previous_was_reorged);
}

BOOST_AUTO_TEST_CASE(reorg_after_positive_check_is_not_cached)
{
    PolicySetup setup;
    std::string error;
    const BTCHeaderPolicy policy{setup.Policy()};
    BOOST_REQUIRE(policy.CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error));

    setup.backend.chain_tips.push_back(
        ChainTip{NonNullHash(777), 100, "valid-fork"});
    BOOST_CHECK(!policy.CheckCandidate(
        setup.config, setup.tip, setup.previous, setup.NOW, error));
    BOOST_CHECK(error.find("btc-recent-fork") == 0);
}

BOOST_AUTO_TEST_CASE(candidate_never_moves_backward_in_bitcoin_height)
{
    PolicySetup setup;
    setup.config.max_lag_blocks = 0;
    std::string error;
    BOOST_CHECK(!setup.Policy().CheckCandidate(
        setup.config, setup.old, setup.previous, setup.NOW, error));
    BOOST_CHECK(error.find("btc-non-monotonic-height") == 0);
}

BOOST_AUTO_TEST_CASE(payment_audit_range_binds_active_h_plus_37)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(later_tip,
                                  Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};

    std::string error;
    const auto range{setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(range, error);
    BOOST_CHECK(range->anchor_hash == setup.tip);
    BOOST_CHECK_EQUAL(range->anchor_height, 100);
    BOOST_CHECK(range->future_hash == future);
    BOOST_CHECK_EQUAL(range->future_height, 137);
}

BOOST_AUTO_TEST_CASE(payment_audit_range_has_no_b_time_anchor_lag_limit)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 later_tip{NonNullHash(180)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 81;
    setup.backend.headers.emplace(future, Header{137, 44, setup.NOW - 300});
    setup.backend.headers.emplace(later_tip,
                                  Header{180, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(180, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 180, "active"}};

    std::string error;
    BOOST_REQUIRE_MESSAGE(setup.Policy().CheckPaymentAuditActiveRange(
                              setup.config, setup.tip, setup.NOW, error),
                          error);
}

BOOST_AUTO_TEST_CASE(
    payment_audit_and_reset_range_requires_six_confirmations_and_one_view)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 short_tip{NonNullHash(141)};
    setup.backend.best_hash = short_tip;
    setup.backend.headers[setup.tip].confirmations = 42;
    setup.backend.headers.emplace(future, Header{137, 5, setup.NOW - 300});
    setup.backend.headers.emplace(short_tip,
                                  Header{141, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(141, short_tip);
    setup.backend.chain_tips = {ChainTip{short_tip, 141, "active"}};

    std::string error;
    BOOST_CHECK(!setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error));
    BOOST_CHECK(error.find("btc-audit-future-unconfirmed") == 0);

    const uint256 confirmed_tip{NonNullHash(142)};
    setup.backend.best_hash = confirmed_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers[future].confirmations = 5; // stale/racing view
    setup.backend.headers.emplace(confirmed_tip,
                                  Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(142, confirmed_tip);
    setup.backend.chain_tips = {ChainTip{confirmed_tip, 142, "active"}};
    BOOST_CHECK(!setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-audit-future-tip-inconsistent");

    setup.backend.headers[future].confirmations = 6;
    const auto confirmed{setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(confirmed, error);
    BOOST_CHECK(confirmed->future_hash == future);
    BOOST_CHECK_EQUAL(confirmed->future_height, 137);
}

BOOST_AUTO_TEST_CASE(reset_beacon_rejects_a_claimed_non_active_h_plus_37_hash)
{
    PolicySetup setup;
    const uint256 active_future{NonNullHash(137)};
    const uint256 claimed_future{NonNullHash(10'137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        active_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        claimed_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        later_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, active_future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};

    std::string error;
    const auto range{setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(range, error);
    BOOST_CHECK(range->future_hash == active_future);
    BOOST_CHECK(range->future_hash != claimed_future);
}

BOOST_AUTO_TEST_CASE(reset_beacon_range_is_rechecked_after_bitcoin_view_change)
{
    PolicySetup setup;
    const uint256 first_future{NonNullHash(137)};
    const uint256 replacement_future{NonNullHash(20'137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        first_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        replacement_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        later_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, first_future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};

    const BTCHeaderPolicy policy{setup.Policy()};
    std::string error;
    const auto first{policy.CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(first, error);
    BOOST_CHECK(first->future_hash == first_future);

    setup.backend.active_hashes[137] = replacement_future;
    const auto second{policy.CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(second, error);
    BOOST_CHECK(second->future_hash == replacement_future);
    BOOST_CHECK(second->future_hash != first->future_hash);
}

BOOST_AUTO_TEST_CASE(payment_audit_and_reset_range_rejects_reorged_anchor)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(later_tip,
                                  Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes[100] = NonNullHash(10'100);
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};

    std::string error;
    BOOST_CHECK(!setup.Policy().CheckPaymentAuditActiveRange(
        setup.config, setup.tip, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-audit-anchor-not-active-chain");
}

BOOST_AUTO_TEST_CASE(active_range_classifies_only_mature_stable_anchor_reorg)
{
    PolicySetup setup;
    setup.config.min_confirmations = 20;
    const uint256 replacement_anchor{NonNullHash(10'100)};
    const uint256 short_tip{NonNullHash(141)};
    setup.backend.best_hash = short_tip;
    setup.backend.headers[setup.tip].confirmations = -1;
    setup.backend.headers.emplace(
        replacement_anchor, Header{100, 42, setup.NOW - 600});
    setup.backend.headers.emplace(
        short_tip, Header{141, 1, setup.NOW - 30});
    setup.backend.active_hashes[100] = replacement_anchor;
    setup.backend.active_hashes.emplace(141, short_tip);
    setup.backend.chain_tips = {ChainTip{short_tip, 141, "active"}};

    std::string error;
    const auto immature{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_CHECK(immature.status == BTCHeaderActiveRangeStatus::WAITING);
    BOOST_CHECK(!immature.range);
    BOOST_CHECK(error.find("btc-audit-inactive-anchor-immature") == 0);
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockhash"], 2U);
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockchaininfo"], 2U);

    const uint256 mature_tip{NonNullHash(142)};
    setup.backend.method_calls.clear();
    setup.backend.best_hash = mature_tip;
    setup.backend.headers[replacement_anchor].confirmations = 43;
    setup.backend.headers.emplace(
        mature_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(142, mature_tip);
    setup.backend.chain_tips = {ChainTip{mature_tip, 142, "active"}};
    const auto mature{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_CHECK(mature.status ==
                BTCHeaderActiveRangeStatus::STABLE_ANCHOR_INACTIVE);
    BOOST_CHECK(!mature.range);
    BOOST_CHECK_EQUAL(error, "btc-audit-anchor-not-active-chain");
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockhash"], 2U);
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockchaininfo"], 2U);

    const auto wrong_height{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/99,
        setup.NOW, error)};
    BOOST_CHECK(wrong_height.status == BTCHeaderActiveRangeStatus::TRANSIENT);
    BOOST_CHECK_EQUAL(error, "btc-audit-anchor-height-mismatch");
}

BOOST_AUTO_TEST_CASE(rollover_proof_binds_one_stable_inactive_and_active_view)
{
    PolicySetup setup;
    const uint256 observed_old_active{NonNullHash(10'100)};
    const uint256 replacement{NonNullHash(10'140)};
    const uint256 mature_tip{NonNullHash(142)};
    setup.backend.best_hash = mature_tip;
    setup.backend.headers[setup.tip].confirmations = -1;
    setup.backend.headers.emplace(
        observed_old_active, Header{100, 43, setup.NOW - 600});
    setup.backend.headers.emplace(
        replacement, Header{140, 3, setup.NOW - 90});
    setup.backend.headers.emplace(
        mature_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes[100] = observed_old_active;
    setup.backend.active_hashes.emplace(140, replacement);
    setup.backend.active_hashes.emplace(142, mature_tip);
    setup.backend.chain_tips = {ChainTip{mature_tip, 142, "active"}};

    std::string error;
    BOOST_CHECK(
        !setup.Policy().AuthorizeStableInactiveAnchorReplacement(
            setup.config, setup.tip, /*expected_anchor_height=*/100,
            replacement, setup.previous, uint256{}, setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-rollover-context-null");

    const auto proof{
        setup.Policy().AuthorizeStableInactiveAnchorReplacement(
            setup.config, setup.tip, /*expected_anchor_height=*/100,
            replacement, setup.previous, NonNullHash(10'200),
            setup.NOW, error)};
    BOOST_REQUIRE_MESSAGE(proof, error);
    BOOST_CHECK(proof->AnchorHash() == setup.tip);
    BOOST_CHECK_EQUAL(proof->AnchorHeight(), 100);
    BOOST_CHECK(proof->ReplacementHash() == replacement);
    BOOST_CHECK_EQUAL(proof->ReplacementHeight(), 140);
    BOOST_CHECK(proof->ObservedActiveHash() == observed_old_active);
    BOOST_CHECK(proof->StableTipHash() == mature_tip);
    BOOST_CHECK_EQUAL(proof->StableTipHeight(), 142);
    BOOST_CHECK_EQUAL(proof->RequiredMaturityHeight(), 142);

    const uint256 future{NonNullHash(137)};
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        future, Header{137, 6, setup.NOW - 300});
    setup.backend.active_hashes[100] = setup.tip;
    setup.backend.active_hashes.emplace(137, future);
    BOOST_CHECK(
        !setup.Policy().AuthorizeStableInactiveAnchorReplacement(
            setup.config, setup.tip, /*expected_anchor_height=*/100,
            replacement, setup.previous, NonNullHash(10'200),
            setup.NOW, error));
    BOOST_CHECK_EQUAL(error,
                      "btc-rollover-anchor-not-stably-inactive");
}

BOOST_AUTO_TEST_CASE(inactive_anchor_maturity_overflow_is_transient)
{
    PolicySetup setup;
    constexpr int32_t tip_height{std::numeric_limits<int32_t>::max()};
    constexpr int32_t anchor_height{tip_height - 41};
    const uint256 anchor{NonNullHash(30'100)};
    const uint256 observed_active{NonNullHash(40'100)};
    const uint256 tip{NonNullHash(40'142)};
    setup.backend.best_hash = tip;
    setup.backend.headers.clear();
    setup.backend.active_hashes.clear();
    setup.backend.headers.emplace(
        anchor, Header{anchor_height, -1, setup.NOW - 600});
    setup.backend.headers.emplace(
        tip, Header{tip_height, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(anchor_height, observed_active);
    setup.backend.active_hashes.emplace(tip_height, tip);
    setup.backend.chain_tips = {
        ChainTip{tip, tip_height, "active"}};

    std::string error;
    const auto checked{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, anchor, anchor_height, setup.NOW, error)};
    BOOST_CHECK(checked.status == BTCHeaderActiveRangeStatus::TRANSIENT);
    BOOST_CHECK_EQUAL(
        error, "btc-audit-inactive-anchor-maturity-overflow");
}

BOOST_AUTO_TEST_CASE(rollover_proof_rejects_cross_view_replacement_reorg)
{
    PolicySetup setup;
    const uint256 observed_old_active{NonNullHash(10'100)};
    const uint256 replacement{NonNullHash(10'140)};
    const uint256 replacement_after_reorg{NonNullHash(20'140)};
    const uint256 mature_tip{NonNullHash(142)};
    setup.backend.best_hash = mature_tip;
    setup.backend.headers[setup.tip].confirmations = -1;
    setup.backend.headers.emplace(
        replacement, Header{140, 3, setup.NOW - 90});
    setup.backend.headers.emplace(
        mature_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes[100] = observed_old_active;
    setup.backend.active_hashes.emplace(140, replacement);
    setup.backend.active_hashes.emplace(142, mature_tip);
    setup.backend.chain_tips = {ChainTip{mature_tip, 142, "active"}};
    setup.backend.before_call = [&](const std::vector<std::string>& args,
                                    std::size_t method_call) {
        if (args.front() == "getblockhash" && method_call == 5) {
            setup.backend.active_hashes[140] =
                replacement_after_reorg;
        }
    };

    std::string error;
    BOOST_CHECK(
        !setup.Policy().AuthorizeStableInactiveAnchorReplacement(
            setup.config, setup.tip, /*expected_anchor_height=*/100,
            replacement, setup.previous, NonNullHash(10'200),
            setup.NOW, error));
    BOOST_CHECK_EQUAL(error, "btc-audit-active-view-changed");
}

BOOST_AUTO_TEST_CASE(active_range_rejects_mid_view_anchor_reorg)
{
    PolicySetup setup;
    const uint256 first_replacement{NonNullHash(10'100)};
    const uint256 second_replacement{NonNullHash(20'100)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = -1;
    setup.backend.headers.emplace(
        later_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes[100] = first_replacement;
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};
    setup.backend.before_call = [&](const std::vector<std::string>& args,
                                    std::size_t method_call) {
        if (args.front() == "getblockhash" && method_call == 2) {
            setup.backend.active_hashes[100] = second_replacement;
        }
    };

    std::string error;
    const auto checked{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_CHECK(checked.status == BTCHeaderActiveRangeStatus::TRANSIENT);
    BOOST_CHECK(!checked.range);
    BOOST_CHECK_EQUAL(error, "btc-audit-active-view-changed");
}

BOOST_AUTO_TEST_CASE(active_range_rejects_tip_change_during_rpc)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 first_tip{NonNullHash(142)};
    const uint256 replacement_tip{NonNullHash(20'142)};
    setup.backend.best_hash = first_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        first_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.headers.emplace(
        replacement_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(142, first_tip);
    setup.backend.chain_tips = {ChainTip{first_tip, 142, "active"}};
    setup.backend.before_call = [&](const std::vector<std::string>& args,
                                    std::size_t method_call) {
        if (args.front() != "getblockhash" || method_call != 3) return;
        setup.backend.best_hash = replacement_tip;
        setup.backend.active_hashes[142] = replacement_tip;
        setup.backend.chain_tips = {
            ChainTip{replacement_tip, 142, "active"}};
    };

    std::string error;
    const auto checked{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_CHECK(checked.status == BTCHeaderActiveRangeStatus::TRANSIENT);
    BOOST_CHECK(!checked.range);
    BOOST_CHECK_EQUAL(error, "btc-audit-tip-view-changed");
}

BOOST_AUTO_TEST_CASE(active_range_rejects_changed_h_plus_37_with_same_tip)
{
    PolicySetup setup;
    const uint256 first_future{NonNullHash(137)};
    const uint256 replacement_future{NonNullHash(20'137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        first_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        replacement_future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        later_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, first_future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};
    setup.backend.before_call = [&](const std::vector<std::string>& args,
                                    std::size_t method_call) {
        if (args.front() == "getblockhash" && method_call == 4) {
            setup.backend.active_hashes[137] = replacement_future;
        }
    };

    std::string error;
    const auto checked{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_CHECK(checked.status == BTCHeaderActiveRangeStatus::TRANSIENT);
    BOOST_CHECK(!checked.range);
    BOOST_CHECK_EQUAL(error, "btc-audit-active-view-changed");
}

BOOST_AUTO_TEST_CASE(active_range_ready_repeats_both_active_hashes)
{
    PolicySetup setup;
    const uint256 future{NonNullHash(137)};
    const uint256 later_tip{NonNullHash(142)};
    setup.backend.best_hash = later_tip;
    setup.backend.headers[setup.tip].confirmations = 43;
    setup.backend.headers.emplace(
        future, Header{137, 6, setup.NOW - 300});
    setup.backend.headers.emplace(
        later_tip, Header{142, 1, setup.NOW - 30});
    setup.backend.active_hashes.emplace(137, future);
    setup.backend.active_hashes.emplace(142, later_tip);
    setup.backend.chain_tips = {ChainTip{later_tip, 142, "active"}};

    std::string error;
    const auto checked{setup.Policy().ClassifyPaymentAuditActiveRange(
        setup.config, setup.tip, /*expected_anchor_height=*/100,
        setup.NOW, error)};
    BOOST_REQUIRE(checked.status == BTCHeaderActiveRangeStatus::READY);
    BOOST_REQUIRE(checked.range);
    BOOST_CHECK(checked.range->anchor_hash == setup.tip);
    BOOST_CHECK(checked.range->future_hash == future);
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockhash"], 4U);
    BOOST_CHECK_EQUAL(setup.backend.method_calls["getblockchaininfo"], 2U);
}

BOOST_AUTO_TEST_SUITE_END()
