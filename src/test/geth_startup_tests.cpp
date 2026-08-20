// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/geth_startup.h>

#include <boost/test/unit_test.hpp>

using node::GethStartupWaitState;

BOOST_AUTO_TEST_SUITE(geth_startup_tests)

BOOST_AUTO_TEST_CASE(bootstrap_completion_starts_fresh_normal_timeout)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    BOOST_CHECK(wait.BootstrapActive());
    BOOST_CHECK(!wait.Expired(start + Seconds{66}));

    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{72});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK(!wait.Expired(start + Seconds{101}));
    BOOST_CHECK(wait.Expired(start + Seconds{102}));
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
