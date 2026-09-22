// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa/slhdsa.h>
#include <support/cleanse.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr std::size_t MAX_FUZZ_MESSAGE_SIZE{256};
constexpr std::size_t FIXTURE_CONTEXT_SIZE{21};

struct SLHFixture {
    slhdsa::PublicKey public_key{};
    slhdsa::Signature signature{};
    std::array<std::uint8_t, 32> message{};
    std::array<std::uint8_t, FIXTURE_CONTEXT_SIZE> context{
        'S', 'Y', 'S', 'C', 'O', 'I', 'N', '-', 'S', 'L', 'H', 'D', 'S', 'A', '-',
        'F', 'U', 'Z', 'Z', '-', '1'};
};

SLHFixture g_fixture;

void InitializeSLHFixture()
{
    slhdsa::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i{0}; i < g_fixture.message.size(); ++i) {
        g_fixture.message[i] = static_cast<std::uint8_t>(0xa0 + i);
    }

    auto secret_key = slhdsa::GenerateSecretKey(seed);
    memory_cleanse(seed.data(), seed.size());
    Assert(secret_key.has_value());
    Assert(secret_key->GetPublicKey(g_fixture.public_key));
    Assert(slhdsa::SignDeterministic(*secret_key, g_fixture.message, g_fixture.context,
                                     g_fixture.signature));
    Assert(slhdsa::Verify(g_fixture.public_key, g_fixture.message, g_fixture.context,
                          g_fixture.signature));
}

void VerifyRawFrame(FuzzedDataProvider& provider)
{
    const std::size_t public_key_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, slhdsa::PUBLIC_KEY_SIZE + 1);
    const std::size_t signature_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, slhdsa::SIGNATURE_SIZE + 1);
    const std::size_t message_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, MAX_FUZZ_MESSAGE_SIZE);
    const std::size_t context_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, slhdsa::MAX_CONTEXT_SIZE + 1);

    const auto public_key = provider.ConsumeBytes<std::uint8_t>(public_key_size);
    const auto signature = provider.ConsumeBytes<std::uint8_t>(signature_size);
    const auto message = provider.ConsumeBytes<std::uint8_t>(message_size);
    const auto context = provider.ConsumeBytes<std::uint8_t>(context_size);
    (void)slhdsa::Verify(public_key, message, context, signature);
}

void VerifyMutatedFixture(FuzzedDataProvider& provider)
{
    auto public_key = g_fixture.public_key;
    auto signature = g_fixture.signature;
    auto message = g_fixture.message;
    auto context = g_fixture.context;
    bool pristine{true};

    LIMITED_WHILE(provider.remaining_bytes() != 0, 8) {
        const std::uint8_t region = provider.ConsumeIntegralInRange<std::uint8_t>(0, 3);
        const std::uint8_t delta = provider.ConsumeIntegral<std::uint8_t>();
        pristine &= delta == 0;
        if (region == 0) {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(0, public_key.size() - 1);
            public_key[offset] ^= delta;
        } else if (region == 1) {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(0, signature.size() - 1);
            signature[offset] ^= delta;
        } else if (region == 2) {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(0, message.size() - 1);
            message[offset] ^= delta;
        } else {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(0, context.size() - 1);
            context[offset] ^= delta;
        }
    }

    const bool verified = slhdsa::Verify(public_key, message, context, signature);
    if (pristine) assert(verified);
}

void VerifyFixtureLengthBoundaries(FuzzedDataProvider& provider)
{
    std::array<std::uint8_t, slhdsa::PUBLIC_KEY_SIZE + 1> public_key{};
    std::array<std::uint8_t, slhdsa::SIGNATURE_SIZE + 1> signature{};
    std::array<std::uint8_t, slhdsa::MAX_CONTEXT_SIZE + 1> context{};
    std::copy(g_fixture.public_key.begin(), g_fixture.public_key.end(), public_key.begin());
    std::copy(g_fixture.signature.begin(), g_fixture.signature.end(), signature.begin());
    std::copy(g_fixture.context.begin(), g_fixture.context.end(), context.begin());

    constexpr std::array<std::size_t, 3> PUBLIC_KEY_SIZES{
        slhdsa::PUBLIC_KEY_SIZE, slhdsa::PUBLIC_KEY_SIZE - 1, slhdsa::PUBLIC_KEY_SIZE + 1};
    constexpr std::array<std::size_t, 3> SIGNATURE_SIZES{
        slhdsa::SIGNATURE_SIZE, slhdsa::SIGNATURE_SIZE - 1, slhdsa::SIGNATURE_SIZE + 1};
    constexpr std::array<std::size_t, 3> CONTEXT_SIZES{
        FIXTURE_CONTEXT_SIZE, slhdsa::MAX_CONTEXT_SIZE, slhdsa::MAX_CONTEXT_SIZE + 1};

    const std::size_t public_key_size = PUBLIC_KEY_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, PUBLIC_KEY_SIZES.size() - 1)];
    const std::size_t signature_size = SIGNATURE_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, SIGNATURE_SIZES.size() - 1)];
    const std::size_t context_size = CONTEXT_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, CONTEXT_SIZES.size() - 1)];

    const bool verified = slhdsa::Verify(
        std::span<const std::uint8_t>{public_key}.first(public_key_size), g_fixture.message,
        std::span<const std::uint8_t>{context}.first(context_size),
        std::span<const std::uint8_t>{signature}.first(signature_size));
    if (public_key_size != slhdsa::PUBLIC_KEY_SIZE ||
        signature_size != slhdsa::SIGNATURE_SIZE || context_size > slhdsa::MAX_CONTEXT_SIZE) {
        assert(!verified);
    } else if (context_size == g_fixture.context.size()) {
        assert(verified);
    }
}

void VerifyFixtureMessageAndContext(FuzzedDataProvider& provider)
{
    const std::size_t message_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, MAX_FUZZ_MESSAGE_SIZE);
    const std::size_t context_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, slhdsa::MAX_CONTEXT_SIZE + 1);
    const auto message = provider.ConsumeBytes<std::uint8_t>(message_size);
    const auto context = provider.ConsumeBytes<std::uint8_t>(context_size);
    (void)slhdsa::Verify(g_fixture.public_key, message, context, g_fixture.signature);
}

} // namespace

FUZZ_TARGET(pq_slhdsa_verify, .init = InitializeSLHFixture)
{
    if (buffer.empty()) return;
    const auto framed_input = buffer.subspan(1);
    FuzzedDataProvider provider{framed_input.data(), framed_input.size()};
    switch (buffer.front() & 0x07) {
    case 1:
        VerifyMutatedFixture(provider);
        break;
    case 2:
        VerifyFixtureLengthBoundaries(provider);
        break;
    case 3:
        VerifyFixtureMessageAndContext(provider);
        break;
    default:
        VerifyRawFrame(provider);
        break;
    }
}
