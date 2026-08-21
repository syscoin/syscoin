// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <crypto/slhdsa/selftest.h>
#include <crypto/sphincs_c11/sphincs_c11.h>
#include <support/cleanse.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstddef>

BOOST_AUTO_TEST_SUITE(pq_crypto_tests)

BOOST_AUTO_TEST_CASE(slhdsa_shake_128s_kat)
{
    BOOST_CHECK(slhdsa::RunSelfTest());
}

BOOST_AUTO_TEST_CASE(sphincs_c11_sha_kat)
{
    sphincs_c11::SecretSeed secret_seed;
    sphincs_c11::PublicSeed public_seed;
    sphincs_c11::Message message;
    for (size_t i = 0; i < secret_seed.size(); ++i) secret_seed[i] = i;
    for (size_t i = 0; i < public_seed.size(); ++i) public_seed[i] = 0xa0 + i;
    for (size_t i = 0; i < message.size(); ++i) message[i] = (3 + 7 * i) & 0xff;

    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(secret_seed, public_seed, public_key, secret_key));

    sphincs_c11::Signature signature;
    BOOST_REQUIRE(sphincs_c11::Sign(secret_key, message, signature));
    BOOST_CHECK(sphincs_c11::Verify(public_key, message, signature));

    const auto public_bytes = sphincs_c11::SerializePublicKey(public_key);
    sphincs_c11::PublicKey parsed_public_key;
    BOOST_CHECK(sphincs_c11::ParsePublicKey(public_bytes, parsed_public_key));
    BOOST_CHECK(!sphincs_c11::ParsePublicKey(
        Span<const unsigned char>{public_bytes}.first(public_bytes.size() - 1),
        parsed_public_key));

    auto secret_bytes = sphincs_c11::SerializeSecretKey(secret_key);
    sphincs_c11::SecretKey parsed_secret_key;
    BOOST_CHECK(sphincs_c11::ParseSecretKey(secret_bytes, parsed_secret_key));
    secret_bytes.back() ^= 1;
    BOOST_CHECK(!sphincs_c11::ParseSecretKey(secret_bytes, parsed_secret_key));
    BOOST_CHECK_EQUAL(
        HexStr(public_bytes),
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafa3d1b4ec763f8be45e4a56375774efe9");

    std::array<unsigned char, CSHA256::OUTPUT_SIZE> signature_digest;
    CSHA256().Write(signature.data(), signature.size()).Finalize(signature_digest.data());
    BOOST_CHECK_EQUAL(
        HexStr(signature_digest),
        "99c0656fccd9353d4b68db3f4d09afc1485c9cc59381ff5603208a25be026886");

    sphincs_c11::Signature second_signature;
    BOOST_REQUIRE(sphincs_c11::Sign(secret_key, message, second_signature));
    BOOST_CHECK(signature == second_signature);

    auto changed_message = message;
    changed_message.front() ^= 1;
    BOOST_CHECK(!sphincs_c11::Verify(public_key, changed_message, signature));
    BOOST_CHECK(!sphincs_c11::Verify(
        public_key, message,
        Span<const unsigned char>{signature}.first(signature.size() - 1)));

    auto noncanonical_counter = second_signature;
    constexpr std::size_t FIRST_WOTS_COUNTER_OFFSET{2336 + 43 * 16};
    noncanonical_counter[FIRST_WOTS_COUNTER_OFFSET] =
        static_cast<unsigned char>(sphincs_c11::GRIND_LIMIT >> 24);
    noncanonical_counter[FIRST_WOTS_COUNTER_OFFSET + 1] =
        static_cast<unsigned char>(sphincs_c11::GRIND_LIMIT >> 16);
    noncanonical_counter[FIRST_WOTS_COUNTER_OFFSET + 2] =
        static_cast<unsigned char>(sphincs_c11::GRIND_LIMIT >> 8);
    noncanonical_counter[FIRST_WOTS_COUNTER_OFFSET + 3] =
        static_cast<unsigned char>(sphincs_c11::GRIND_LIMIT);
    BOOST_CHECK(!sphincs_c11::Verify(public_key, message,
                                     noncanonical_counter));

    signature.front() ^= 1;
    BOOST_CHECK(!sphincs_c11::Verify(public_key, message, signature));
    const std::array batch_inputs{
        sphincs_c11::VerificationInput{&public_key, &message, second_signature},
        sphincs_c11::VerificationInput{&public_key, &message, signature},
    };
    const auto batch_results = sphincs_c11::VerifyBatch(batch_inputs);
    BOOST_REQUIRE_EQUAL(batch_results.size(), 2U);
    BOOST_CHECK_EQUAL(batch_results[0], 1);
    BOOST_CHECK_EQUAL(batch_results[1], 0);
    memory_cleanse(secret_bytes.data(), secret_bytes.size());
    memory_cleanse(secret_seed.data(), secret_seed.size());
}

BOOST_AUTO_TEST_SUITE_END()
