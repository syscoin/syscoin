// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/scheduled_wots/scheduled_wots.h>
#include <support/cleanse.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace {

constexpr std::array<std::uint32_t, 4> FIXTURE_LEAVES{0, 230, 231, 234};

struct ScheduledWotsFixture {
    scheduled_wots::PublicKey public_key{};
    scheduled_wots::Message message{};
    std::array<scheduled_wots::Signature, FIXTURE_LEAVES.size()> signatures{};
};

ScheduledWotsFixture g_fixture;

void InitializeScheduledWotsFixture()
{
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
    }
    for (std::size_t i{0}; i < g_fixture.message.size(); ++i) {
        g_fixture.message[i] = static_cast<std::uint8_t>(3 + 7 * i);
    }

    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    Assert(secret_key.has_value());
    Assert(secret_key->GetPublicKey(g_fixture.public_key));
    for (std::size_t i{0}; i < FIXTURE_LEAVES.size(); ++i) {
        Assert(scheduled_wots::SignDeterministic(
            *secret_key, FIXTURE_LEAVES[i], g_fixture.message,
            g_fixture.signatures[i]));
        Assert(scheduled_wots::Verify(
            g_fixture.public_key, FIXTURE_LEAVES[i], g_fixture.message,
            g_fixture.signatures[i]));
    }
    memory_cleanse(seed.data(), seed.size());
}

void VerifyRawFrame(FuzzedDataProvider& provider)
{
    const std::size_t public_key_size{
        provider.ConsumeIntegralInRange<std::size_t>(
            0, scheduled_wots::PUBLIC_KEY_SIZE + 1)};
    const std::size_t signature_size{
        provider.ConsumeIntegralInRange<std::size_t>(
            0, scheduled_wots::SIGNATURE_SIZE + 1)};
    const auto public_key{provider.ConsumeBytes<std::uint8_t>(public_key_size)};
    const auto signature{provider.ConsumeBytes<std::uint8_t>(signature_size)};
    scheduled_wots::Message message{};
    provider.ConsumeData(message.data(), message.size());
    const std::uint32_t leaf{provider.ConsumeIntegral<std::uint32_t>()};

    (void)scheduled_wots::Verify(public_key, leaf, message, signature);
}

void VerifyMutatedFixture(FuzzedDataProvider& provider)
{
    const std::size_t fixture_index{
        provider.ConsumeIntegralInRange<std::size_t>(
            0, FIXTURE_LEAVES.size() - 1)};
    auto public_key{g_fixture.public_key};
    auto message{g_fixture.message};
    auto signature{g_fixture.signatures[fixture_index]};
    std::uint32_t leaf{FIXTURE_LEAVES[fixture_index]};
    bool pristine{true};

    LIMITED_WHILE(provider.remaining_bytes() != 0, 8) {
        const std::uint8_t region{
            provider.ConsumeIntegralInRange<std::uint8_t>(0, 3)};
        if (region == 3) {
            const std::uint32_t delta{provider.ConsumeIntegral<std::uint32_t>()};
            leaf ^= delta;
            pristine &= delta == 0;
            continue;
        }

        const std::uint8_t delta{provider.ConsumeIntegral<std::uint8_t>()};
        pristine &= delta == 0;
        if (region == 0) {
            const std::size_t offset{
                provider.ConsumeIntegralInRange<std::size_t>(
                    0, public_key.size() - 1)};
            public_key[offset] ^= delta;
        } else if (region == 1) {
            const std::size_t offset{
                provider.ConsumeIntegralInRange<std::size_t>(
                    0, message.size() - 1)};
            message[offset] ^= delta;
        } else {
            const std::size_t offset{
                provider.ConsumeIntegralInRange<std::size_t>(
                    0, signature.size() - 1)};
            signature[offset] ^= delta;
        }
    }

    const bool verified{
        scheduled_wots::Verify(public_key, leaf, message, signature)};
    if (pristine) assert(verified);
}

void VerifyLeafBoundaries(FuzzedDataProvider& provider)
{
    constexpr std::array<std::uint32_t, 6> LEAVES{
        0, 230, 231, 234, scheduled_wots::AUTHORIZED_LEAF_COUNT,
        std::numeric_limits<std::uint32_t>::max()};
    const std::size_t index{provider.ConsumeIntegralInRange<std::size_t>(
        0, LEAVES.size() - 1)};
    const std::size_t signature_index{
        index < FIXTURE_LEAVES.size() ? index : 0};
    const bool verified{scheduled_wots::Verify(
        g_fixture.public_key, LEAVES[index], g_fixture.message,
        g_fixture.signatures[signature_index])};

    assert(verified == (index < FIXTURE_LEAVES.size()));
}

void VerifyLengthBoundaries(FuzzedDataProvider& provider)
{
    std::array<std::uint8_t, scheduled_wots::PUBLIC_KEY_SIZE + 1> public_key{};
    std::array<std::uint8_t, scheduled_wots::SIGNATURE_SIZE + 1> signature{};
    std::copy(g_fixture.public_key.begin(), g_fixture.public_key.end(),
              public_key.begin());
    std::copy(g_fixture.signatures[1].begin(), g_fixture.signatures[1].end(),
              signature.begin());

    constexpr std::array<std::size_t, 3> PUBLIC_KEY_SIZES{
        scheduled_wots::PUBLIC_KEY_SIZE - 1,
        scheduled_wots::PUBLIC_KEY_SIZE,
        scheduled_wots::PUBLIC_KEY_SIZE + 1};
    constexpr std::array<std::size_t, 3> SIGNATURE_SIZES{
        scheduled_wots::SIGNATURE_SIZE - 1,
        scheduled_wots::SIGNATURE_SIZE,
        scheduled_wots::SIGNATURE_SIZE + 1};
    const std::size_t public_key_size{PUBLIC_KEY_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(
            0, PUBLIC_KEY_SIZES.size() - 1)]};
    const std::size_t signature_size{SIGNATURE_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(
            0, SIGNATURE_SIZES.size() - 1)]};

    const bool verified{scheduled_wots::Verify(
        std::span<const std::uint8_t>{public_key}.first(public_key_size),
        230, g_fixture.message,
        std::span<const std::uint8_t>{signature}.first(signature_size))};
    assert(verified ==
           (public_key_size == scheduled_wots::PUBLIC_KEY_SIZE &&
            signature_size == scheduled_wots::SIGNATURE_SIZE));
}

} // namespace

FUZZ_TARGET(pq_scheduled_wots_verify, .init = InitializeScheduledWotsFixture)
{
    if (buffer.empty()) return;
    FuzzedDataProvider provider{buffer.data() + 1, buffer.size() - 1};
    switch (buffer.front() & 0x03) {
    case 1:
        VerifyMutatedFixture(provider);
        break;
    case 2:
        VerifyLeafBoundaries(provider);
        break;
    case 3:
        VerifyLengthBoundaries(provider);
        break;
    default:
        VerifyRawFrame(provider);
        break;
    }
}
