// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * See https://www.boost.org/doc/libs/1_78_0/libs/test/doc/html/boost_test/adv_scenarios/single_header_customizations/multiple_translation_units.html
 */
#define BOOST_TEST_MODULE Syscoin Core Test Suite
#define BOOST_TEST_NO_MAIN

#include <boost/test/included/unit_test.hpp>

#include <test/util/setup_common.h>
#include <test/util/pq_crypto_worker.h>

#include <functional>
#include <iostream>

int main(int argc, char* argv[])
{
    // Self-exec workers must enter before Boost fixtures create node threads.
    if (const auto result = pq_test_crypto::TryWorkerMain(argc, argv)) return *result;
#ifdef BOOST_TEST_ALTERNATIVE_INIT_API
    return boost::unit_test::unit_test_main(&init_unit_test, argc, argv);
#else
    return boost::unit_test::unit_test_main(&init_unit_test_suite, argc, argv);
#endif
}

/** Redirect debug log to unit_test.log files */
const std::function<void(const std::string&)> G_TEST_LOG_FUN = [](const std::string& s) {
    static const bool should_log{std::any_of(
        &boost::unit_test::framework::master_test_suite().argv[1],
        &boost::unit_test::framework::master_test_suite().argv[boost::unit_test::framework::master_test_suite().argc],
        [](const char* arg) {
            return std::string{"DEBUG_LOG_OUT"} == arg;
        })};
    if (!should_log) return;
    std::cout << s;
};

/**
 * Retrieve the command line arguments from boost.
 * Allows usage like:
 * `test_syscoin --run_test="net_tests/cnode_listen_port" -- -checkaddrman=1 -printtoconsole=1`
 * which would return `["-checkaddrman=1", "-printtoconsole=1"]`.
 */
const std::function<std::vector<const char*>()> G_TEST_COMMAND_LINE_ARGUMENTS = []() {
    std::vector<const char*> args;
    for (int i = 1; i < boost::unit_test::framework::master_test_suite().argc; ++i) {
        args.push_back(boost::unit_test::framework::master_test_suite().argv[i]);
    }
    return args;
};
