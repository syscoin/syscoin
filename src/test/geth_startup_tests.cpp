// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/geth_startup.h>
#include <zmq/zmqutil.h>

#include <boost/test/unit_test.hpp>

using node::GethStartupWaitState;

BOOST_AUTO_TEST_SUITE(geth_startup_tests)

BOOST_AUTO_TEST_CASE(nevm_block_info_legacy_response)
{
    for (const auto& count : {"0", "1", "123456", "18446744073709551615"}) {
        uint64_t height{999};
        std::string state{"previous-error"};
        BOOST_REQUIRE(ParseNEVMBlockInfoResponse({"nevmblockinfo", count}, height, state));
        BOOST_CHECK_EQUAL(height, std::stoull(count));
        BOOST_CHECK(state.empty());
    }
}

BOOST_AUTO_TEST_CASE(nevm_block_info_paired_response)
{
    uint64_t height{999};
    std::string state;
    // sysgeth sends 64 display-order hex characters, including a null hash at genesis.
    BOOST_REQUIRE(ParseNEVMBlockInfoResponse({"nevmblockinfo", "0", std::string(64, '0')}, height, state));
    BOOST_CHECK_EQUAL(height, 0U);
    const std::string hash{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_REQUIRE(ParseNEVMBlockInfoResponse({"nevmblockinfo", "123456", hash}, height, state));
    BOOST_CHECK_EQUAL(height, 123456U);
    BOOST_CHECK(state.empty());
}

BOOST_AUTO_TEST_CASE(nevm_block_info_malformed_response)
{
    const std::string hash(64, 'a');
    const std::vector<std::vector<std::string>> invalid{
        {}, {"nevmblockinfo"}, {"nevmblockinfo", "1", hash, "extra"},
        {"nevmblock", "1"}, {std::string("nevmblockinfo\0", 14), "1"},
        {"nevmblockinfo", ""}, {"nevmblockinfo", "unavailable", hash},
        {"nevmblockinfo", "-1"}, {"nevmblockinfo", " 1"}, {"nevmblockinfo", "1 "},
        {"nevmblockinfo", "1.0"}, {"nevmblockinfo", std::string("1\0", 2)},
        {"nevmblockinfo", "18446744073709551616"}, {"nevmblockinfo", std::string(100, '1')},
        {"nevmblockinfo", "1", ""}, {"nevmblockinfo", "1", std::string(32, 'a')},
        {"nevmblockinfo", "1", std::string(63, 'a')}, {"nevmblockinfo", "1", std::string(65, 'a')},
        {"nevmblockinfo", "1", "0x" + hash}, {"nevmblockinfo", "1", std::string(64, 'g')},
        {"nevmblockinfo", "1", std::string(63, 'a') + '\0'},
        {"nevmblockinfo", "1", std::string(63, 'a') + ' '},
        {"nevmblockinfo", "0", hash}, {"nevmblockinfo", "1", std::string(64, '0')},
    };
    for (const auto& parts : invalid) {
        uint64_t height{999};
        std::string state;
        BOOST_CHECK(!ParseNEVMBlockInfoResponse(parts, height, state));
        BOOST_CHECK_EQUAL(height, 999U);
        BOOST_CHECK(!state.empty());
    }
}

BOOST_AUTO_TEST_CASE(bootstrap_completion_starts_fresh_normal_timeout)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    BOOST_CHECK(wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{66}).count(), 64);
    BOOST_CHECK(!wait.Expired(start + Seconds{66}));

    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{72});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{101}).count(), 29);
    BOOST_CHECK(!wait.Expired(start + Seconds{101}));
    BOOST_CHECK(wait.Expired(start + Seconds{102}));
}

BOOST_AUTO_TEST_CASE(bootstrap_status_flicker_does_not_consume_final_completion_grace)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{72});
    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{73});
    BOOST_CHECK(wait.BootstrapActive());

    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{200});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{229}).count(), 29);
    BOOST_CHECK(!wait.Expired(start + Seconds{229}));
    BOOST_CHECK(wait.Expired(start + Seconds{230}));
}

BOOST_AUTO_TEST_CASE(dead_geth_does_not_gain_post_bootstrap_grace)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/false, start + Seconds{20});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK(wait.Expired(start + Seconds{30}));
}

BOOST_AUTO_TEST_CASE(zero_timeout_remains_unbounded)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds::zero(), Seconds::zero()};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    BOOST_CHECK(!wait.Expired(start + Seconds{100000}));
    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{100001});
    BOOST_CHECK(!wait.Expired(start + Seconds{200000}));
}

BOOST_AUTO_TEST_SUITE_END()
