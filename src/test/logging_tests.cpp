// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/common.h>
#include <logging.h>
#include <logging/timer.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <chrono>
#include <fstream>
#include <future>
#include <iostream>
#include <limits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static void ResetLogger()
{
    LogInstance().SetLogLevel(BCLog::DEFAULT_LOG_LEVEL);
    LogInstance().SetCategoryLogLevel({});
}

struct LogSetup : public BasicTestingSetup {
    fs::path prev_log_path;
    fs::path tmp_log_path;
    bool prev_reopen_file;
    bool prev_print_to_file;
    bool prev_log_timestamps;
    bool prev_log_threadnames;
    bool prev_log_sourcelocations;
    std::unordered_map<BCLog::LogFlags, BCLog::Level> prev_category_levels;
    BCLog::Level prev_log_level;

    LogSetup() : prev_log_path{LogInstance().m_file_path},
                 tmp_log_path{m_args.GetDataDirBase() / "tmp_debug.log"},
                 prev_reopen_file{LogInstance().m_reopen_file},
                 prev_print_to_file{LogInstance().m_print_to_file},
                 prev_log_timestamps{LogInstance().m_log_timestamps},
                 prev_log_threadnames{LogInstance().m_log_threadnames},
                 prev_log_sourcelocations{LogInstance().m_log_sourcelocations},
                 prev_category_levels{LogInstance().CategoryLevels()},
                 prev_log_level{LogInstance().LogLevel()}
    {
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        // Prevent tests from failing when the line number of the logs changes.
        LogInstance().m_log_sourcelocations = false;

        LogInstance().SetLogLevel(BCLog::Level::Debug);
        LogInstance().SetCategoryLogLevel({});
    }

    ~LogSetup()
    {
        LogInstance().SetRateLimiting(nullptr);
        LogInstance().m_file_path = prev_log_path;
        LogPrintf("Sentinel log to reopen log file\n");
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
        LogInstance().SetLogLevel(prev_log_level);
        LogInstance().SetCategoryLogLevel(prev_category_levels);
    }
};

BOOST_AUTO_TEST_CASE(logging_timer)
{
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    const std::string_view result_prefix{"tests: msg ("};
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("msg").substr(0, result_prefix.size()), result_prefix);
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintf_, LogSetup)
{
    LogInstance().m_log_sourcelocations = true;
    LogPrintf_("fn1", "src1", 1, BCLog::LogFlags::NET, BCLog::Level::Debug, "foo1: %s\n", "bar1");
    LogPrintf_("fn2", "src2", 2, BCLog::LogFlags::NET, BCLog::Level::None, "foo2: %s\n", "bar2");
    LogPrintf_("fn3", "src3", 3, BCLog::LogFlags::NONE, BCLog::Level::Debug, "foo3: %s\n", "bar3");
    LogPrintf_("fn4", "src4", 4, BCLog::LogFlags::NONE, BCLog::Level::None, "foo4: %s\n", "bar4");
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    std::vector<std::string> expected = {
        "[src1:1] [fn1] [net:debug] foo1: bar1",
        "[src2:2] [fn2] [net] foo2: bar2",
        "[src3:3] [fn3] [debug] foo3: bar3",
        "[src4:4] [fn4] foo4: bar4",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros, LogSetup)
{
    LogPrintf("foo5: %s\n", "bar5");
    LogPrint(BCLog::NET, "foo6: %s\n", "bar6");
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "foo7: %s\n", "bar7");
    LogPrintLevel(BCLog::NET, BCLog::Level::Info, "foo8: %s\n", "bar8");
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo9: %s\n", "bar9");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo10: %s\n", "bar10");
    LogPrintfCategory(BCLog::VALIDATION, "foo11: %s\n", "bar11");
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    std::vector<std::string> expected = {
        "foo5: bar5",
        "[net] foo6: bar6",
        "[net:debug] foo7: bar7",
        "[net:info] foo8: bar8",
        "[net:warning] foo9: bar9",
        "[net:error] foo10: bar10",
        "[validation] foo11: bar11",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros_CategoryName, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    const auto concatenated_category_names = LogInstance().LogCategoriesString();
    std::vector<std::pair<BCLog::LogFlags, std::string>> expected_category_names;
    const auto category_names = SplitString(concatenated_category_names, ',');
    for (const auto& category_name : category_names) {
        BCLog::LogFlags category;
        const auto trimmed_category_name = TrimString(category_name);
        BOOST_REQUIRE(GetLogCategory(category, trimmed_category_name));
        expected_category_names.emplace_back(category, trimmed_category_name);
    }

    std::vector<std::string> expected;
    for (const auto& [category, name] : expected_category_names) {
        LogPrint(category, "foo: %s\n", "bar");
        std::string expected_log = "[";
        expected_log += name;
        expected_log += "] foo: bar";
        expected.push_back(expected_log);
    }

    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_SeverityLevels, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);

    LogInstance().SetLogLevel(BCLog::Level::Debug);
    LogInstance().SetCategoryLogLevel(/*category_str=*/"net", /*level_str=*/"info");

    // Global log level
    LogPrintLevel(BCLog::HTTP, BCLog::Level::Info, "foo1: %s\n", "bar1");
    LogPrintLevel(BCLog::MEMPOOL, BCLog::Level::Trace, "foo2: %s. This log level is lower than the global one.\n", "bar2");
    LogPrintLevel(BCLog::VALIDATION, BCLog::Level::Warning, "foo3: %s\n", "bar3");
    LogPrintLevel(BCLog::RPC, BCLog::Level::Error, "foo4: %s\n", "bar4");

    // Category-specific log level
    LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "foo5: %s\n", "bar5");
    LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "foo6: %s. This log level is the same as the global one but lower than the category-specific one, which takes precedence. \n", "bar6");
    LogPrintLevel(BCLog::NET, BCLog::Level::Error, "foo7: %s\n", "bar7");

    std::vector<std::string> expected = {
        "[http:info] foo1: bar1",
        "[validation:warning] foo3: bar3",
        "[rpc:error] foo4: bar4",
        "[net:warning] foo5: bar5",
        "[net:error] foo7: bar7",
    };
    std::ifstream file{tmp_log_path};
    std::vector<std::string> log_lines;
    for (std::string log; std::getline(file, log);) {
        log_lines.push_back(log);
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_Conf, LogSetup)
{
    // Set global log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"syscoind", "-loglevel=debug"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);
    }

    // Set category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"syscoind", "-loglevel=net:trace"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::DEFAULT_LOG_LEVEL);

        const auto& category_levels{LogInstance().CategoryLevels()};
        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_REQUIRE(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);
    }

    // Set both global log level and category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"syscoind", "-loglevel=debug", "-loglevel=net:trace", "-loglevel=http:info"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(4, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);

        const auto& category_levels{LogInstance().CategoryLevels()};
        BOOST_CHECK_EQUAL(category_levels.size(), 2);

        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_CHECK(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);

        const auto http_it{category_levels.find(BCLog::LogFlags::HTTP)};
        BOOST_CHECK(http_it != category_levels.end());
        BOOST_CHECK_EQUAL(http_it->second, BCLog::Level::Info);
    }
}

BOOST_AUTO_TEST_CASE(logging_rate_limiter_boundaries)
{
    BCLog::LogRateLimiter limiter{1024, std::chrono::seconds{60}};
    using Status = BCLog::LogRateLimiter::Status;
    BOOST_CHECK(!limiter.SuppressionsActive());
    limiter.Reset();
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, 1023) == Status::UNSUPPRESSED);
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, 1) == Status::UNSUPPRESSED);
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, 1) == Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, 1) == Status::STILL_SUPPRESSED);
    // File and line identify independent quotas, including calls through helpers.
    BOOST_CHECK(limiter.Consume("two", "source.cpp", 2, 1024) == Status::UNSUPPRESSED);
    BOOST_CHECK(limiter.Consume("one", "other.cpp", 1, 1024) == Status::UNSUPPRESSED);
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, std::numeric_limits<uint64_t>::max()) == Status::STILL_SUPPRESSED);
    limiter.Reset();
    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK(limiter.Consume("one", "source.cpp", 1, 1024) == Status::UNSUPPRESSED);
}

static std::string ReadLog(const fs::path& path)
{
    std::ifstream file{path};
    return {std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}

BOOST_FIXTURE_TEST_CASE(logging_disk_quota_and_reset, LogSetup)
{
    auto limiter = std::make_shared<BCLog::LogRateLimiter>(64, std::chrono::seconds{20});
    LogInstance().SetRateLimiting(limiter);
    const std::string message(31, 'a');
    auto log = [&] {
        LogInstance().LogPrintStr(message + "\n", "one", "quota.cpp", 1, BCLog::NONE, BCLog::Level::None);
    };
    log();
    log();
    BOOST_CHECK_EQUAL(ReadLog(tmp_log_path), message + "\n" + message + "\n");
    log();
    const auto suppressed = ReadLog(tmp_log_path);
    BOOST_CHECK(suppressed.find("Excessive logging from quota.cpp:1") != std::string::npos);
    for (int i = 0; i < 100; ++i) log();
    BOOST_CHECK_EQUAL(ReadLog(tmp_log_path), suppressed);

    // Another source still reaches disk, and a dropped entry still reaches callbacks.
    std::string callback_message;
    auto callback = LogInstance().PushBackCallback([&](const std::string& str) { callback_message = str; });
    log();
    LogInstance().DeleteCallback(callback);
    BOOST_CHECK(callback_message.find(message) != std::string::npos);
    BOOST_CHECK_EQUAL(ReadLog(tmp_log_path), suppressed);
    LogInstance().LogPrintStr("unrelated\n", "two", "quota.cpp", 2, BCLog::NONE, BCLog::Level::None);
    BOOST_CHECK(ReadLog(tmp_log_path).find("unrelated\n") != std::string::npos);

    // Exercise the same scheduler reset as production without a wall-clock sleep.
    CScheduler scheduler;
    scheduler.scheduleEvery([weak = std::weak_ptr{limiter}] {
        if (auto locked = weak.lock()) locked->Reset();
    }, limiter->m_reset_window);
    scheduler.MockForward(limiter->m_reset_window);
    std::promise<void> synced;
    scheduler.scheduleFromNow([&] { synced.set_value(); }, std::chrono::milliseconds{0});
    scheduler.m_service_thread = std::thread([&] { scheduler.serviceQueue(); });
    synced.get_future().wait();
    scheduler.stop();
    BOOST_CHECK(!limiter->SuppressionsActive());
    BOOST_CHECK(ReadLog(tmp_log_path).find("Restarting disk logging from quota.cpp:1") != std::string::npos);
    const auto reset_size = ReadLog(tmp_log_path).size();
    log();
    BOOST_CHECK_EQUAL(ReadLog(tmp_log_path).size(), reset_size + message.size() + 1);
}

static LogErrorFormat CaptureErrorFormat(LogErrorFormat format)
{
    return format;
}

BOOST_AUTO_TEST_CASE(logging_error_format_call_sites)
{
    const int first_line = __LINE__ + 1;
    const auto first = CaptureErrorFormat("first implicit conversion");
    BOOST_CHECK_EQUAL(first.source_file, __FILE__);
    BOOST_CHECK_EQUAL(first.source_line, first_line);
    BOOST_CHECK(std::string{first.source_function}.find(__func__) != std::string::npos);

    const auto other_caller = [] {
        const int line = __LINE__ + 1;
        return std::pair{CaptureErrorFormat("second implicit conversion"), line};
    };
    const auto [second, second_line] = other_caller();
    BOOST_CHECK_EQUAL(second.source_file, __FILE__);
    BOOST_CHECK_EQUAL(second.source_line, second_line);
    BOOST_CHECK_NE(first.source_line, second.source_line);
    BOOST_CHECK_NE(std::string{first.source_function}, std::string{second.source_function});
}

BOOST_FIXTURE_TEST_CASE(logging_error_source_location, LogSetup)
{
    LogInstance().m_log_sourcelocations = true;
    const int line = __LINE__ + 1;
    BOOST_CHECK(!error("source-location marker %d", 42));
    const auto logged = ReadLog(tmp_log_path);
    const auto expected_location = "[" + RemovePrefix(std::string{__FILE__}, "./") + ":" + std::to_string(line) + "] [";
    BOOST_CHECK(logged.find(expected_location) != std::string::npos);
    BOOST_CHECK(logged.find("ERROR: source-location marker 42") != std::string::npos);
}

BOOST_FIXTURE_TEST_CASE(logging_debug_exempt_and_error_callers, LogSetup)
{
    LogInstance().SetRateLimiting(std::make_shared<BCLog::LogRateLimiter>(128));
    auto debug = [] { LogPrint(BCLog::NET, "debug exempt\n"); };
    for (int i = 0; i < 100; ++i) debug();
    BOOST_CHECK(ReadLog(tmp_log_path).find("Excessive logging") == std::string::npos);

    auto error_one = [] { return error("source one"); };
    auto error_two = [] { return error("source two"); };
    for (int i = 0; i < 100; ++i) BOOST_CHECK(!error_one());
    const auto suppressed = ReadLog(tmp_log_path);
    BOOST_CHECK(suppressed.find("Excessive logging") != std::string::npos);
    BOOST_CHECK(!error_two());
    BOOST_CHECK(ReadLog(tmp_log_path).find("ERROR: source two") != std::string::npos);
    BOOST_CHECK_GT(ReadLog(tmp_log_path).size(), suppressed.size());
}

BOOST_AUTO_TEST_SUITE_END()
