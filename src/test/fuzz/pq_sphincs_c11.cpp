// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sphincs_c11/sphincs_c11.h>
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

namespace {

// These offsets are part of the locked C11-SHA signature profile: the two
// hypertree layers each serialize WOTS bytes, a big-endian counter, and an auth path.
constexpr std::size_t WOTS_BYTES{43 * 16};
constexpr std::size_t FIRST_WOTS_COUNTER_OFFSET{2336 + WOTS_BYTES};
constexpr std::size_t HT_LAYER_SIZE{WOTS_BYTES + sizeof(std::uint32_t) + 8 * 16};
constexpr std::array<std::size_t, 2> WOTS_COUNTER_OFFSETS{
    FIRST_WOTS_COUNTER_OFFSET, FIRST_WOTS_COUNTER_OFFSET + HT_LAYER_SIZE};
static_assert(2336 + WOTS_COUNTER_OFFSETS.size() * HT_LAYER_SIZE ==
              sphincs_c11::SIGNATURE_SIZE);
static_assert(WOTS_COUNTER_OFFSETS.back() + sizeof(std::uint32_t) <=
              sphincs_c11::SIGNATURE_SIZE);

struct C11Fixture {
    sphincs_c11::SerializedPublicKey public_key{};
    sphincs_c11::Message message{};
    sphincs_c11::Signature signature{};
};

C11Fixture g_fixture;

void PutBE32(sphincs_c11::Signature& signature, std::size_t offset, std::uint32_t value)
{
    signature[offset] = static_cast<unsigned char>(value >> 24);
    signature[offset + 1] = static_cast<unsigned char>(value >> 16);
    signature[offset + 2] = static_cast<unsigned char>(value >> 8);
    signature[offset + 3] = static_cast<unsigned char>(value);
}

void InitializeC11Fixture()
{
    sphincs_c11::SecretSeed secret_seed{};
    sphincs_c11::PublicSeed public_seed{};
    for (std::size_t i{0}; i < secret_seed.size(); ++i) {
        secret_seed[i] = static_cast<unsigned char>(i);
    }
    for (std::size_t i{0}; i < public_seed.size(); ++i) {
        public_seed[i] = static_cast<unsigned char>(0xa0 + i);
    }
    for (std::size_t i{0}; i < g_fixture.message.size(); ++i) {
        g_fixture.message[i] = static_cast<unsigned char>((3 + 7 * i) & 0xff);
    }

    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    Assert(sphincs_c11::GenerateKeyPair(secret_seed, public_seed, public_key, secret_key));
    g_fixture.public_key = sphincs_c11::SerializePublicKey(public_key);
    Assert(sphincs_c11::Sign(secret_key, g_fixture.message, g_fixture.signature));
    Assert(sphincs_c11::Verify(public_key, g_fixture.message, g_fixture.signature));
    memory_cleanse(secret_seed.data(), secret_seed.size());
}

void VerifyRawFrame(FuzzedDataProvider& provider)
{
    const std::size_t public_key_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, sphincs_c11::PUBLIC_KEY_SIZE + 1);
    const std::size_t signature_size = provider.ConsumeIntegralInRange<std::size_t>(
        0, sphincs_c11::SIGNATURE_SIZE + 1);
    const auto public_key_bytes = provider.ConsumeBytes<unsigned char>(public_key_size);
    const auto signature = provider.ConsumeBytes<unsigned char>(signature_size);
    sphincs_c11::Message message{};
    provider.ConsumeData(message.data(), message.size());

    sphincs_c11::PublicKey public_key;
    if (!sphincs_c11::ParsePublicKey(public_key_bytes, public_key)) return;
    (void)sphincs_c11::Verify(public_key, message, signature);
}

void VerifyMutatedFixture(FuzzedDataProvider& provider)
{
    auto public_key_bytes = g_fixture.public_key;
    auto message = g_fixture.message;
    auto signature = g_fixture.signature;
    bool pristine{true};

    LIMITED_WHILE(provider.remaining_bytes() != 0, 8) {
        const std::uint8_t region = provider.ConsumeIntegralInRange<std::uint8_t>(0, 2);
        const unsigned char delta = provider.ConsumeIntegral<unsigned char>();
        pristine &= delta == 0;
        if (region == 0) {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(
                0, public_key_bytes.size() - 1);
            public_key_bytes[offset] ^= delta;
        } else if (region == 1) {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(0, message.size() - 1);
            message[offset] ^= delta;
        } else {
            const auto offset = provider.ConsumeIntegralInRange<std::size_t>(
                0, signature.size() - 1);
            signature[offset] ^= delta;
        }
    }

    sphincs_c11::PublicKey public_key;
    Assert(sphincs_c11::ParsePublicKey(public_key_bytes, public_key));
    const bool verified = sphincs_c11::Verify(public_key, message, signature);
    if (pristine) assert(verified);
}

void VerifyCounterMutation(FuzzedDataProvider& provider)
{
    auto signature = g_fixture.signature;
    constexpr std::array<std::uint32_t, 4> BOUNDARY_VALUES{
        sphincs_c11::GRIND_LIMIT, sphincs_c11::GRIND_LIMIT - 1, 0,
        std::numeric_limits<std::uint32_t>::max()};
    const std::size_t layer = provider.ConsumeIntegralInRange<std::size_t>(
        0, WOTS_COUNTER_OFFSETS.size() - 1);
    const std::uint32_t counter = provider.ConsumeBool()
        ? provider.ConsumeIntegral<std::uint32_t>()
        : BOUNDARY_VALUES[provider.ConsumeIntegralInRange<std::size_t>(0,
                                                                       BOUNDARY_VALUES.size() - 1)];
    PutBE32(signature, WOTS_COUNTER_OFFSETS[layer], counter);

    sphincs_c11::PublicKey public_key;
    Assert(sphincs_c11::ParsePublicKey(g_fixture.public_key, public_key));
    const bool verified = sphincs_c11::Verify(public_key, g_fixture.message, signature);
    if (counter >= sphincs_c11::GRIND_LIMIT) assert(!verified);
}

void VerifyLengthBoundaries(FuzzedDataProvider& provider)
{
    std::array<unsigned char, sphincs_c11::PUBLIC_KEY_SIZE + 1> public_key_bytes{};
    std::array<unsigned char, sphincs_c11::SIGNATURE_SIZE + 1> signature{};
    std::copy(g_fixture.public_key.begin(), g_fixture.public_key.end(), public_key_bytes.begin());
    std::copy(g_fixture.signature.begin(), g_fixture.signature.end(), signature.begin());

    constexpr std::array<std::size_t, 3> PUBLIC_KEY_SIZES{
        sphincs_c11::PUBLIC_KEY_SIZE, sphincs_c11::PUBLIC_KEY_SIZE - 1,
        sphincs_c11::PUBLIC_KEY_SIZE + 1};
    constexpr std::array<std::size_t, 3> SIGNATURE_SIZES{
        sphincs_c11::SIGNATURE_SIZE, sphincs_c11::SIGNATURE_SIZE - 1,
        sphincs_c11::SIGNATURE_SIZE + 1};
    const std::size_t public_key_size = PUBLIC_KEY_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, PUBLIC_KEY_SIZES.size() - 1)];
    const std::size_t signature_size = SIGNATURE_SIZES[
        provider.ConsumeIntegralInRange<std::size_t>(0, SIGNATURE_SIZES.size() - 1)];

    sphincs_c11::PublicKey public_key;
    const bool parsed = sphincs_c11::ParsePublicKey(
        Span<const unsigned char>{public_key_bytes}.first(public_key_size), public_key);
    if (public_key_size != sphincs_c11::PUBLIC_KEY_SIZE) {
        assert(!parsed);
        return;
    }
    assert(parsed);
    const bool verified = sphincs_c11::Verify(
        public_key, g_fixture.message,
        Span<const unsigned char>{signature}.first(signature_size));
    if (signature_size == sphincs_c11::SIGNATURE_SIZE) {
        assert(verified);
    } else {
        assert(!verified);
    }
}

} // namespace

FUZZ_TARGET(pq_sphincs_c11_verify, .init = InitializeC11Fixture)
{
    if (buffer.empty()) return;
    const auto framed_input = buffer.subspan(1);
    FuzzedDataProvider provider{framed_input.data(), framed_input.size()};
    switch (buffer.front() & 0x03) {
    case 1:
        VerifyMutatedFixture(provider);
        break;
    case 2:
        VerifyCounterMutation(provider);
        break;
    case 3:
        VerifyLengthBoundaries(provider);
        break;
    default:
        VerifyRawFrame(provider);
        break;
    }
}
