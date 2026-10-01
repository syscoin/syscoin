// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license; see COPYING.
// Diagnostic only: production signing on synthetic 32-byte registration digests.
#include <crypto/slhdsa/slhdsa.h>

#include <array>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>
#include <sched.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
using Clock = std::chrono::steady_clock;
constexpr std::array<uint32_t, 4> MEMBERS{0, 267, 400, 800};
constexpr std::string_view DOMAIN{"SYS_PQ_GLOBAL_REGISTER_V1"};
static_assert(DOMAIN.size() == 25);
const auto START = Clock::now();
std::mutex output_mutex;

struct Options {
    unsigned workers;
    std::vector<int> cpus;
    std::filesystem::path output_dir;
    std::vector<std::size_t> members;
};

unsigned ParseUnsigned(std::string_view value)
{
    unsigned number{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), number);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::runtime_error("expected a nonnegative decimal integer");
    }
    return number;
}

Options ParseOptions(int argc, char* argv[])
{
    std::optional<unsigned> workers;
    std::optional<std::string_view> cpu_list;
    std::optional<std::filesystem::path> output_dir;
    std::optional<unsigned> member;
    for (int argument{1}; argument < argc; argument += 2) {
        const std::string_view flag{argv[argument]};
        if (argument + 1 >= argc) throw std::runtime_error("missing option value");
        const std::string_view value{argv[argument + 1]};
        if (flag == "--workers" && !workers) {
            workers = ParseUnsigned(value);
        } else if (flag == "--cpus" && !cpu_list) {
            cpu_list = value;
        } else if (flag == "--output-dir" && !output_dir) {
            output_dir = std::filesystem::path{value};
        } else if (flag == "--member" && !member) {
            member = ParseUnsigned(value);
        } else {
            throw std::runtime_error("unknown or repeated option");
        }
    }
    if (!workers || !cpu_list || !output_dir) {
        throw std::runtime_error("required: --workers 1|2|4 --cpus CPU[,CPU...] --output-dir DIRECTORY [--member 0|1|2|3]");
    }
    if (*workers != 1 && *workers != 2 && *workers != 4) {
        throw std::runtime_error("workers must be 1, 2, or 4");
    }
    if (member && (*member >= MEMBERS.size() || *workers != 1)) {
        throw std::runtime_error("member must be 0 through 3 and requires one worker");
    }
    Options options{*workers, {}, *output_dir, {}};
    auto remaining = *cpu_list;
    while (true) {
        const auto comma = remaining.find(',');
        const auto cpu = ParseUnsigned(remaining.substr(0, comma));
        if (cpu >= CPU_SETSIZE) throw std::runtime_error("CPU ID exceeds supported affinity set size");
        options.cpus.push_back(static_cast<int>(cpu));
        if (comma == std::string_view::npos) break;
        remaining.remove_prefix(comma + 1);
    }
    if (options.cpus.size() != options.workers) {
        throw std::runtime_error("CPU count must equal worker count");
    }
    if (!std::filesystem::is_directory(options.output_dir)) {
        throw std::runtime_error("output directory must already exist");
    }
    if (member) {
        options.members.push_back(*member);
    } else {
        for (std::size_t index{0}; index < MEMBERS.size(); ++index) options.members.push_back(index);
    }
    return options;
}

double Seconds(Clock::duration duration)
{
    return std::chrono::duration<double>(duration).count();
}

rusage Usage(int who)
{
    rusage result{};
    if (getrusage(who, &result) != 0) throw std::runtime_error("getrusage failed");
    return result;
}

double TimevalSeconds(timeval value)
{
    return static_cast<double>(value.tv_sec) + static_cast<double>(value.tv_usec) / 1'000'000;
}

void PinWorker(int cpu)
{
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
        throw std::system_error(errno, std::generic_category(), "sched_setaffinity failed for CPU " + std::to_string(cpu));
    }
}

void Event(const char* phase, const char* event, unsigned workers, unsigned worker,
           int requested_cpu, std::size_t index, double wall_seconds,
           const rusage& before, const rusage& after)
{
    const int cpu = sched_getcpu();
    if (cpu < 0 || cpu != requested_cpu) throw std::runtime_error("worker CPU affinity mismatch");
    const std::lock_guard lock{output_mutex};
    std::printf("{\"phase\":\"%s\",\"event\":\"%s\",\"workers\":%u,\"worker\":%u,"
                "\"member_index\":%zu,\"member\":%u,\"requested_cpu\":%d,\"cpu\":%d,"
                "\"tid\":%ld,\"elapsed_s\":%.6f,\"wall_s\":%.6f,\"user_s\":%.6f,"
                "\"system_s\":%.6f,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld}\n",
                phase, event, workers, worker, index, MEMBERS[index], requested_cpu, cpu,
                syscall(SYS_gettid), Seconds(Clock::now() - START), wall_seconds,
                TimevalSeconds(after.ru_utime) - TimevalSeconds(before.ru_utime),
                TimevalSeconds(after.ru_stime) - TimevalSeconds(before.ru_stime),
                after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
    std::fflush(stdout);
}

template <typename Job>
void Batch(const char* phase, const Options& options, const Job& job)
{
    const auto start = Clock::now();
    const auto before = Usage(RUSAGE_SELF);
    std::vector<std::exception_ptr> failures(options.workers);
    std::vector<std::thread> threads;
    threads.reserve(options.workers);
    struct JoinGuard {
        std::vector<std::thread>& threads;
        ~JoinGuard() { for (auto& thread : threads) if (thread.joinable()) thread.join(); }
    };
    {
        JoinGuard guard{threads};
        for (unsigned worker{0}; worker < options.workers; ++worker) {
            threads.emplace_back([&, worker] {
                try {
                    PinWorker(options.cpus[worker]);
                    for (std::size_t position{worker}; position < options.members.size(); position += options.workers) {
                        const auto index = options.members[position];
                        const auto operation_before = Usage(RUSAGE_THREAD);
                        Event(phase, "start", options.workers, worker, options.cpus[worker], index, 0,
                              operation_before, operation_before);
                        // Progress output and verification stay outside this interval.
                        const auto timed_start = Clock::now();
                        const auto timed_before = Usage(RUSAGE_THREAD);
                        if (!job(index)) throw std::runtime_error("crypto operation failed");
                        const auto timed_after = Usage(RUSAGE_THREAD);
                        const double wall_seconds = Seconds(Clock::now() - timed_start);
                        Event(phase, "complete", options.workers, worker, options.cpus[worker], index,
                              wall_seconds, timed_before, timed_after);
                    }
                } catch (...) {
                    failures[worker] = std::current_exception();
                }
            });
        }
    }
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    const auto after = Usage(RUSAGE_SELF);
    std::printf("{\"phase\":\"%s\",\"event\":\"batch_complete\",\"workers\":%u,"
                "\"operations\":%zu,\"wall_s\":%.6f,\"user_s\":%.6f,\"system_s\":%.6f,"
                "\"peak_rss_kib\":%ld}\n", phase, options.workers, options.members.size(), Seconds(Clock::now() - start),
                TimevalSeconds(after.ru_utime) - TimevalSeconds(before.ru_utime),
                TimevalSeconds(after.ru_stime) - TimevalSeconds(before.ru_stime), after.ru_maxrss);
    std::fflush(stdout);
}
} // namespace

int main(int argc, char* argv[])
{
    try {
        const auto options = ParseOptions(argc, argv);
        std::printf("{\"event\":\"profile_start\",\"hardware_concurrency\":%u,\"pid\":%ld,"
                    "\"workers\":%u,\"member_count\":%zu,"
                    "\"message_kind\":\"synthetic_32_byte_registration_digest\"}\n",
                    std::thread::hardware_concurrency(), static_cast<long>(getpid()),
                    options.workers, options.members.size());
        std::fflush(stdout);
        std::array<std::optional<slhdsa::SecretKey>, MEMBERS.size()> keys;
        std::array<slhdsa::PublicKey, MEMBERS.size()> public_keys{};
        std::array<std::array<uint8_t, 32>, MEMBERS.size()> messages{};
        std::array<slhdsa::Signature, MEMBERS.size()> signatures{};
        for (const auto index : options.members) {
            for (std::size_t byte{0}; byte < messages[index].size(); ++byte) {
                messages[index][byte] = static_cast<uint8_t>((MEMBERS[index] + byte) & 0xffU);
            }
        }
        Batch("keygen", options, [&](std::size_t index) {
            slhdsa::KeyGenerationSeed seed{};
            seed[0] = 0x72;
            for (std::size_t byte{0}; byte < sizeof(uint32_t); ++byte) {
                seed[1 + byte] = static_cast<uint8_t>(MEMBERS[index] >> (8 * byte));
            }
            keys[index] = slhdsa::GenerateSecretKey(seed);
            return keys[index] && keys[index]->GetPublicKey(public_keys[index]);
        });
        std::printf("{\"event\":\"ready\",\"workers\":%u,\"member_count\":%zu}\n",
                    options.workers, options.members.size());
        std::fflush(stdout);
        if (std::getchar() != '\n') throw std::runtime_error("controller barrier requires one newline byte");
        const std::span<const uint8_t> context{
            reinterpret_cast<const uint8_t*>(DOMAIN.data()), DOMAIN.size()};
        Batch("sign", options, [&](std::size_t index) {
            return slhdsa::SignDeterministic(*keys[index], messages[index], context, signatures[index]);
        });
        // The controller releases verification only when every signing process finishes.
        if (std::getchar() != '\n') throw std::runtime_error("verification barrier requires one newline byte");
        for (const auto index : options.members) {
            if (!slhdsa::Verify(public_keys[index], messages[index], context, signatures[index])) {
                throw std::runtime_error("signature verification failed");
            }
        }
        for (const auto index : options.members) {
            std::ofstream output;
            output.exceptions(std::ios::failbit | std::ios::badbit);
            output.open(options.output_dir / ("member-" + std::to_string(index) + ".sig"), std::ios::binary);
            output.write(reinterpret_cast<const char*>(signatures[index].data()), signatures[index].size());
            output.close();
        }
        std::printf("{\"event\":\"profile_complete\",\"signatures_verified\":%zu,\"member_count\":%zu}\n",
                    options.members.size(), options.members.size());
        std::fflush(stdout);
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "profile failed: %s\n", error.what());
        return 1;
    } catch (...) {
        std::fprintf(stderr, "profile failed: unknown exception\n");
        return 1;
    }
}
