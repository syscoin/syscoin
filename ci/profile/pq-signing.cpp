// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license; see COPYING.
// Diagnostic only: production signing on synthetic 32-byte registration digests.
#include <crypto/slhdsa/slhdsa.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>
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

void Event(const char* phase, const char* event, unsigned workers, std::size_t index,
           double wall_seconds, const rusage& before, const rusage& after)
{
    const std::lock_guard lock{output_mutex};
    std::printf("{\"phase\":\"%s\",\"event\":\"%s\",\"workers\":%u,\"member\":%u,"
                "\"tid\":%ld,\"elapsed_s\":%.6f,\"wall_s\":%.6f,\"user_s\":%.6f,"
                "\"system_s\":%.6f,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld}\n",
                phase, event, workers, MEMBERS[index], syscall(SYS_gettid),
                Seconds(Clock::now() - START), wall_seconds,
                TimevalSeconds(after.ru_utime) - TimevalSeconds(before.ru_utime),
                TimevalSeconds(after.ru_stime) - TimevalSeconds(before.ru_stime),
                after.ru_nvcsw - before.ru_nvcsw, after.ru_nivcsw - before.ru_nivcsw);
    std::fflush(stdout);
}

template <typename Job>
void Batch(const char* phase, unsigned count, const Job& job)
{
    const auto start = Clock::now();
    const auto before = Usage(RUSAGE_SELF);
    std::atomic_size_t next{0};
    std::array<std::exception_ptr, MEMBERS.size()> failures{};
    std::vector<std::thread> threads;
    struct JoinGuard {
        std::vector<std::thread>& threads;
        ~JoinGuard() { for (auto& thread : threads) if (thread.joinable()) thread.join(); }
    };
    {
        JoinGuard guard{threads};
        for (unsigned worker{0}; worker < count; ++worker) {
            threads.emplace_back([&] {
                while (true) {
                    const auto index = next.fetch_add(1, std::memory_order_relaxed);
                    if (index >= MEMBERS.size()) return;
                    try {
                        const auto operation_before = Usage(RUSAGE_THREAD);
                        Event(phase, "start", count, index, 0,
                              operation_before, operation_before);
                        // Progress output and verification stay outside this interval.
                        const auto timed_start = Clock::now();
                        const auto timed_before = Usage(RUSAGE_THREAD);
                        if (!job(index)) throw std::runtime_error("crypto operation failed");
                        const auto timed_after = Usage(RUSAGE_THREAD);
                        const double wall_seconds = Seconds(Clock::now() - timed_start);
                        Event(phase, "complete", count, index, wall_seconds, timed_before, timed_after);
                    } catch (...) {
                        failures[index] = std::current_exception();
                    }
                }
            });
        }
    }
    for (const auto& failure : failures) if (failure) std::rethrow_exception(failure);
    const auto after = Usage(RUSAGE_SELF);
    std::printf("{\"phase\":\"%s\",\"event\":\"batch_complete\",\"workers\":%u,"
                "\"operations\":%zu,\"wall_s\":%.6f,\"user_s\":%.6f,\"system_s\":%.6f,"
                "\"peak_rss_kib\":%ld}\n", phase, count, MEMBERS.size(), Seconds(Clock::now() - start),
                TimevalSeconds(after.ru_utime) - TimevalSeconds(before.ru_utime),
                TimevalSeconds(after.ru_stime) - TimevalSeconds(before.ru_stime), after.ru_maxrss);
    std::fflush(stdout);
}
} // namespace

int main()
{
    try {
        std::printf("{\"event\":\"profile_start\",\"hardware_concurrency\":%u,\"pid\":%ld,"
                    "\"message_kind\":\"synthetic_32_byte_registration_digest\"}\n",
                    std::thread::hardware_concurrency(), static_cast<long>(getpid()));
        std::fflush(stdout);
        std::array<std::optional<slhdsa::SecretKey>, MEMBERS.size()> keys;
        std::array<slhdsa::PublicKey, MEMBERS.size()> public_keys{};
        std::array<std::array<uint8_t, 32>, MEMBERS.size()> messages{};
        std::array<slhdsa::Signature, MEMBERS.size()> serial{}, parallel{};
        for (std::size_t index{0}; index < MEMBERS.size(); ++index) {
            for (std::size_t byte{0}; byte < messages[index].size(); ++byte) {
                messages[index][byte] = static_cast<uint8_t>((MEMBERS[index] + byte) & 0xffU);
            }
        }
        Batch("keygen", 4, [&](std::size_t index) {
            slhdsa::KeyGenerationSeed seed{};
            seed[0] = 0x72;
            for (std::size_t byte{0}; byte < sizeof(uint32_t); ++byte) {
                seed[1 + byte] = static_cast<uint8_t>(MEMBERS[index] >> (8 * byte));
            }
            keys[index] = slhdsa::GenerateSecretKey(seed);
            return keys[index] && keys[index]->GetPublicKey(public_keys[index]);
        });
        const std::span<const uint8_t> context{
            reinterpret_cast<const uint8_t*>(DOMAIN.data()), DOMAIN.size()};
        Batch("sign_serial", 1, [&](std::size_t index) {
            return slhdsa::SignDeterministic(*keys[index], messages[index], context, serial[index]);
        });
        Batch("sign_parallel", 4, [&](std::size_t index) {
            return slhdsa::SignDeterministic(*keys[index], messages[index], context, parallel[index]);
        });
        for (std::size_t index{0}; index < MEMBERS.size(); ++index) {
            if (serial[index] != parallel[index] ||
                !slhdsa::Verify(public_keys[index], messages[index], context, serial[index]) ||
                !slhdsa::Verify(public_keys[index], messages[index], context, parallel[index])) {
                throw std::runtime_error("signature verification or deterministic equality failed");
            }
        }
        std::printf("{\"event\":\"profile_complete\",\"signatures_verified\":8,\"equal_pairs\":4}\n");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "profile failed: %s\n", error.what());
        return 1;
    }
}
