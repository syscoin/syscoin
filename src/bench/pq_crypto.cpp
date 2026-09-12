// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/scheduled_wots/scheduled_wots.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

constexpr std::uint32_t BENCH_LEAF{230};

void Require(bool condition, const char* operation)
{
    if (!condition) {
        throw std::runtime_error{
            std::string{"scheduled-WOTS benchmark failed: "} + operation};
    }
}

scheduled_wots::KeyGenerationSeed ScheduledWotsSeed()
{
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(17 + 13 * i);
    }
    return seed;
}

scheduled_wots::Message ScheduledWotsMessage()
{
    scheduled_wots::Message message{};
    for (std::size_t i{0}; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>(3 + 7 * i);
    }
    return message;
}

struct ScheduledWotsFixture {
    scheduled_wots::KeyGenerationSeed seed{ScheduledWotsSeed()};
    scheduled_wots::Message message{ScheduledWotsMessage()};
    std::optional<scheduled_wots::SecretKey> secret_key{
        scheduled_wots::GenerateSecretKey(seed)};
    scheduled_wots::PublicKey public_key{};
    scheduled_wots::Signature signature{};

    ScheduledWotsFixture()
    {
        Require(secret_key.has_value(), "fixture key generation");
        Require(secret_key->GetPublicKey(public_key), "fixture public key");
        Require(scheduled_wots::SignDeterministic(
                    *secret_key, BENCH_LEAF, message, signature),
                "fixture signing");
        Require(scheduled_wots::Verify(
                    public_key, BENCH_LEAF, message, signature),
                "fixture verification");
    }
};

void ScheduledWotsColdKeyGeneration(benchmark::Bench& bench)
{
    const auto seed{ScheduledWotsSeed()};

    bench.batch(1).unit("cached key").run([&] {
        auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
        Require(secret_key.has_value(), "cold key generation");
        ankerl::nanobench::doNotOptimizeAway(secret_key->CacheBytes());
    });
}

void ScheduledWotsWarmSign(benchmark::Bench& bench)
{
    ScheduledWotsFixture fixture;

    bench.batch(1).unit("signature").run([&] {
        const bool success{scheduled_wots::SignDeterministic(
            *fixture.secret_key, BENCH_LEAF, fixture.message,
            fixture.signature)};
        ankerl::nanobench::doNotOptimizeAway(success);
        ankerl::nanobench::doNotOptimizeAway(fixture.signature);
    });
}

void ScheduledWotsWarmVerify(benchmark::Bench& bench)
{
    const ScheduledWotsFixture fixture;

    bench.batch(1).unit("signature").run([&] {
        const bool success{scheduled_wots::Verify(
            fixture.public_key, BENCH_LEAF, fixture.message,
            fixture.signature)};
        ankerl::nanobench::doNotOptimizeAway(success);
    });
}

} // namespace

BENCHMARK(ScheduledWotsColdKeyGeneration, benchmark::PriorityLevel::LOW);
BENCHMARK(ScheduledWotsWarmSign, benchmark::PriorityLevel::LOW);
BENCHMARK(ScheduledWotsWarmVerify, benchmark::PriorityLevel::HIGH);
