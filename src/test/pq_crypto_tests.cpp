// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/scheduled_wots/scheduled_wots.h>
#include <crypto/sha256.h>
#include <crypto/slhdsa/selftest.h>
#include <support/cleanse.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>

namespace {

scheduled_wots::KeyGenerationSeed ScheduledWotsSeed()
{
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(i);
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

std::array<std::uint8_t, CSHA256::OUTPUT_SIZE> SignatureDigest(
    const scheduled_wots::Signature& signature)
{
    std::array<std::uint8_t, CSHA256::OUTPUT_SIZE> digest{};
    CSHA256().Write(signature.data(), signature.size()).Finalize(digest.data());
    return digest;
}

bool IsAllZero(std::span<const std::uint8_t> bytes)
{
    return std::all_of(bytes.begin(), bytes.end(),
                       [](std::uint8_t value) { return value == 0; });
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_crypto_tests)

BOOST_AUTO_TEST_CASE(slhdsa_shake_128s_kat)
{
    BOOST_CHECK(slhdsa::RunSelfTest());
}

BOOST_AUTO_TEST_CASE(scheduled_wots_shake_kat_and_all_leaves)
{
    auto seed{ScheduledWotsSeed()};
    BOOST_CHECK(!scheduled_wots::GenerateSecretKey(
        std::span<const std::uint8_t>{seed}.first(seed.size() - 1)));

    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    BOOST_CHECK(secret_key->IsValid());
    BOOST_CHECK_EQUAL(secret_key->CacheBytes(),
                      scheduled_wots::TREE_CACHE_BYTES);

    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));
    BOOST_CHECK(!secret_key->GetPublicKey(
        std::span<std::uint8_t>{public_key}.first(public_key.size() - 1)));
    BOOST_CHECK_EQUAL(
        HexStr(public_key),
        "202122232425262728292a2b2c2d2e2f"
        "80820b5fc375938cec8f6e0243346404");

    const auto message{ScheduledWotsMessage()};
    constexpr std::array<std::uint32_t, 4> KAT_LEAVES{0, 230, 231, 234};
    constexpr std::array<std::string_view, KAT_LEAVES.size()> KAT_DIGESTS{
        "6296e80681e63b931587a238f201fc667754ff5de8e55b3f9be018c298876581",
        "98f8a2db99e4efc2bc115841fe4da6c67270b316ce09c536909756a1172eb1ca",
        "902f5c987e9aa043cf506693da16841bba8a8e9c8db7837a41354e494394fb24",
        "3fa60ddc4045dfefb61bbef0bb81970ad4a3b039267f1c790c23a717c8a4542f",
    };

    scheduled_wots::Signature signature{};
    for (std::size_t i{0}; i < KAT_LEAVES.size(); ++i) {
        const std::uint32_t leaf{KAT_LEAVES[i]};
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *secret_key, leaf, message, signature));
        BOOST_CHECK(scheduled_wots::Verify(
            public_key, leaf, message, signature));
        BOOST_CHECK_EQUAL(HexStr(SignatureDigest(signature)), KAT_DIGESTS[i]);

        scheduled_wots::Signature repeated{};
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *secret_key, leaf, message, repeated));
        BOOST_CHECK(repeated == signature);

        const std::uint32_t wrong_leaf{leaf == 0 ? 1U : leaf - 1};
        BOOST_CHECK(!scheduled_wots::Verify(
            public_key, wrong_leaf, message, signature));
    }

    for (std::uint32_t leaf{0};
         leaf < scheduled_wots::AUTHORIZED_LEAF_COUNT; ++leaf) {
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *secret_key, leaf, message, signature));
        BOOST_REQUIRE(scheduled_wots::Verify(
            public_key, leaf, message, signature));
    }

    auto changed_message{message};
    changed_message.front() ^= 1;
    BOOST_CHECK(!scheduled_wots::Verify(
        public_key, 234, changed_message, signature));

    for (const std::size_t offset : std::array<std::size_t, 4>{
             0, scheduled_wots::N,
             scheduled_wots::N + scheduled_wots::WOTS_SIGNATURE_SIZE,
             scheduled_wots::SIGNATURE_SIZE - 1}) {
        auto changed_signature{signature};
        changed_signature[offset] ^= 1;
        BOOST_CHECK(!scheduled_wots::Verify(
            public_key, 234, message, changed_signature));
    }

    BOOST_CHECK(!scheduled_wots::Verify(
        std::span<const std::uint8_t>{public_key}.first(public_key.size() - 1),
        234, message, signature));
    BOOST_CHECK(!scheduled_wots::Verify(
        public_key, 234,
        std::span<const std::uint8_t>{message}.first(message.size() - 1),
        signature));
    BOOST_CHECK(!scheduled_wots::Verify(
        public_key, 234, message,
        std::span<const std::uint8_t>{signature}.first(signature.size() - 1)));

    std::fill(signature.begin(), signature.end(), 0xa5);
    BOOST_CHECK(!scheduled_wots::SignDeterministic(
        *secret_key, scheduled_wots::AUTHORIZED_LEAF_COUNT,
        message, signature));
    BOOST_CHECK(IsAllZero(signature));
    BOOST_CHECK(!scheduled_wots::Verify(
        public_key, scheduled_wots::AUTHORIZED_LEAF_COUNT,
        message, signature));

    std::fill(signature.begin(), signature.end(), 0xa5);
    BOOST_CHECK(!scheduled_wots::SignDeterministic(
        *secret_key, std::numeric_limits<std::uint32_t>::max(),
        message, signature));
    BOOST_CHECK(IsAllZero(signature));

    std::array<std::uint8_t, scheduled_wots::SECRET_KEY_SIZE> encoded{};
    BOOST_REQUIRE(secret_key->Export(encoded));
    BOOST_CHECK_EQUAL(
        HexStr(encoded),
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "80820b5fc375938cec8f6e0243346404");
    BOOST_CHECK(!secret_key->Export(
        std::span<std::uint8_t>{encoded}.first(encoded.size() - 1)));
    BOOST_CHECK(!scheduled_wots::ImportSecretKey(
        std::span<const std::uint8_t>{encoded}.first(encoded.size() - 1)));

    std::array<std::uint8_t, scheduled_wots::SECRET_KEY_SIZE + 1> oversized{};
    std::copy(encoded.begin(), encoded.end(), oversized.begin());
    BOOST_CHECK(!secret_key->Export(oversized));
    BOOST_CHECK(!scheduled_wots::ImportSecretKey(oversized));

    auto imported{scheduled_wots::ImportSecretKey(encoded)};
    BOOST_REQUIRE(imported);
    BOOST_CHECK_EQUAL(imported->CacheBytes(), scheduled_wots::TREE_CACHE_BYTES);
    scheduled_wots::PublicKey imported_public_key{};
    BOOST_REQUIRE(imported->GetPublicKey(imported_public_key));
    BOOST_CHECK(imported_public_key == public_key);
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *imported, 231, message, signature));
    BOOST_CHECK(scheduled_wots::Verify(
        public_key, 231, message, signature));

    encoded.back() ^= 1;
    BOOST_CHECK(!scheduled_wots::ImportSecretKey(encoded));
    encoded.back() ^= 1;

    scheduled_wots::SecretKey moved{std::move(*imported)};
    BOOST_CHECK(!imported->IsValid());
    std::fill(signature.begin(), signature.end(), 0xa5);
    BOOST_CHECK(!scheduled_wots::SignDeterministic(
        *imported, 0, message, signature));
    BOOST_CHECK(IsAllZero(signature));
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        moved, 0, message, signature));
    BOOST_CHECK(scheduled_wots::Verify(
        public_key, 0, message, signature));

    memory_cleanse(encoded.data(), encoded.size());
    memory_cleanse(oversized.data(), oversized.size());
    memory_cleanse(seed.data(), seed.size());
}

BOOST_AUTO_TEST_SUITE_END()
