// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license; see COPYING.
#if defined(HAVE_CONFIG_H)
#include <config/syscoin-config.h>
#endif

#include <test/util/pq_crypto_batch.h>

#if defined(HAVE_BOOST_PROCESS)
#define PQ_TEST_HAS_PROCESS 1
#include <boost/version.hpp>
#if BOOST_VERSION >= 108800
#include <boost/process/v1/args.hpp>
#include <boost/process/v1/child.hpp>
#include <boost/process/v1/exe.hpp>
#include <boost/process/v1/group.hpp>
#include <boost/process/v1/io.hpp>
#include <boost/process/v1/search_path.hpp>
#else
#include <boost/process.hpp>
#endif
#endif

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

namespace pq_test_crypto {

std::size_t RequestedWorkerCount()
{
    const char* value = std::getenv("SYSCOIN_TEST_PQ_CRYPTO_PROCESSES");
    if (value == nullptr || *value == '\0') return 0;
    const std::string_view text{value};
    unsigned workers{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), workers);
    if (error != std::errc{} || end != text.data() + text.size() || workers < 1 || workers > 4) {
        throw std::runtime_error("SYSCOIN_TEST_PQ_CRYPTO_PROCESSES must be 1 through 4");
    }
#ifndef PQ_TEST_HAS_PROCESS
    throw std::runtime_error("PQ subprocess preparation requested without Boost.Process support");
#else
    return workers;
#endif
}

#ifdef PQ_TEST_HAS_PROCESS
namespace {
#if BOOST_VERSION >= 108800
namespace bp = boost::process::v1;
#else
namespace bp = boost::process;
#endif

struct DirectoryGuard {
    std::filesystem::path path;
    ~DirectoryGuard() noexcept
    {
        try {
            std::error_code error;
            std::filesystem::remove_all(path, error);
            if (error) std::fprintf(stderr, "PQ population temporary directory cleanup error %d\n", error.value());
        } catch (...) {
            std::fprintf(stderr, "PQ population temporary directory cleanup failed\n");
        }
    }
};

struct ProcessWave {
    bp::group group;
    std::vector<bp::child> children;
    bool complete{false};

    ~ProcessWave() noexcept
    {
        if (complete) return;
        if (children.empty()) {
            group.detach();
            return;
        }
        // No group wait: that could reap a child's status before exit_code().
        try {
            std::error_code error;
            group.terminate(error);
            if (error) std::fprintf(stderr, "PQ population subprocess group cleanup error %d\n", error.value());
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
            while (true) {
                bool pending{false};
                for (auto& child : children) {
                    error.clear();
                    // running() is nonblocking and captures an exited child's
                    // status. Never pass an expired deadline to Boost wait APIs.
                    if (child.running(error) || error) {
                        pending = true;
                    } else {
                        child.wait(error);
                        if (error) pending = true;
                    }
                }
                if (!pending) break;
                if (std::chrono::steady_clock::now() >= deadline) {
                    std::fprintf(stderr, "PQ population subprocess reap failed within cleanup deadline\n");
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        } catch (...) {
            std::fprintf(stderr, "PQ population subprocess cleanup failed\n");
        }
        group.detach();
    }

    void Finish()
    {
        group.detach();
        complete = true;
    }
};
} // namespace
#endif

std::vector<Result> RunBatches(const std::filesystem::path& executable,
                              const std::filesystem::path& new_directory,
                              const Request& request, std::size_t workers,
                              std::chrono::seconds timeout)
{
#ifndef PQ_TEST_HAS_PROCESS
    throw std::runtime_error("PQ subprocess preparation requires Boost.Process support");
#else
    if (workers < 1 || workers > 4 || request.jobs.empty() || request.jobs.size() > MAX_JOBS ||
        timeout <= std::chrono::seconds{0} || timeout > std::chrono::hours{3}) {
        throw std::runtime_error("Invalid PQ subprocess batch bounds");
    }
    auto program = executable;
    if (!program.has_parent_path() && !std::filesystem::exists(program)) {
        program = std::filesystem::path{bp::search_path(program.string()).native()};
    }
    program = std::filesystem::absolute(program);
    if (!std::filesystem::is_regular_file(program)) {
        throw std::runtime_error("PQ subprocess test executable was not found");
    }
    // Own only a newly created leaf, preventing stale replies and cleanup of an
    // existing directory. Files contain deterministic public test seeds only.
    if (!std::filesystem::create_directory(new_directory)) {
        throw std::runtime_error("PQ subprocess directory already exists");
    }
    DirectoryGuard directory{new_directory};
    // Validate the complete request, including duplicate IDs across partitions.
    WriteRequest(new_directory / "manifest", request);
    const std::size_t count = std::min(workers, request.jobs.size());
    std::vector<Request> partitions(count, Request{request.operation, request.context, {}});
    for (std::size_t index{0}; index < request.jobs.size(); ++index) {
        partitions[index % count].jobs.push_back(request.jobs[index]);
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    ProcessWave wave;
    wave.children.reserve(count);
    std::vector<std::filesystem::path> replies;
    for (std::size_t index{0}; index < count; ++index) {
        const auto input = new_directory / ("request-" + std::to_string(index));
        const auto output = new_directory / ("response-" + std::to_string(index));
        WriteRequest(input, partitions[index]);
        replies.push_back(output);
        // Built-in platform spawn/exec properties only; no custom post-fork hooks.
        using NativeString = std::filesystem::path::string_type;
        const std::vector<NativeString> args{
            std::filesystem::path{WORKER_FLAG}.native(), input.native(), output.native()};
        wave.children.emplace_back(bp::exe = program.native(), bp::args = args,
                                   bp::std_in < bp::null, wave.group);
    }
    std::vector<bool> reaped(count, false);
    std::size_t remaining = count;
    while (remaining != 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error("PQ subprocess preparation deadline expired");
        }
        for (std::size_t index{0}; index < count; ++index) {
            std::error_code error;
            if (std::filesystem::exists(replies[index]) && std::filesystem::file_size(replies[index]) > 7 * 1024 * 1024) {
                throw std::runtime_error("PQ subprocess response exceeded its size limit");
            }
            if (reaped[index]) continue;
            const bool running = wave.children[index].running(error);
            if (error) throw std::system_error(error, "PQ subprocess status check");
            if (running) continue;
            wave.children[index].wait(error);
            if (error) throw std::system_error(error, "PQ subprocess wait");
            const int status = wave.children[index].exit_code();
            if (status != 0) {
                throw std::runtime_error("PQ subprocess worker " + std::to_string(index) +
                                         " exited " + std::to_string(status));
            }
            reaped[index] = true;
            --remaining;
        }
        if (remaining != 0) std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    wave.Finish();
    std::vector<Result> results(request.jobs.size());
    for (std::size_t worker{0}; worker < count; ++worker) {
        const auto reply = ReadResponse(replies[worker], partitions[worker]);
        for (std::size_t index{0}; index < reply.size(); ++index) {
            results[worker + index * count] = reply[index];
        }
    }
    for (std::size_t index{0}; index < results.size(); ++index) {
        if (results[index].member != request.jobs[index].member) {
            throw std::runtime_error("PQ subprocess merged result order mismatch");
        }
    }
    return results;
#endif
}
} // namespace pq_test_crypto
