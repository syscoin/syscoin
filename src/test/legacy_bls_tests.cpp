// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/legacy_bls.h>

#include <clientversion.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdint>

BOOST_AUTO_TEST_SUITE(legacy_bls_tests)

template <size_t Size>
void CheckOpaqueRoundTrip()
{
    std::array<uint8_t, Size> bytes;
    for (size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<uint8_t>((i * 131U + 17U) & 0xffU);
    }

    CLegacyBLSBlob<Size> blob{Span{bytes}};
    BOOST_CHECK(blob.IsValid());
    BOOST_CHECK_EQUAL(blob.ToString().size(), Size * 2);

    CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
    encoded << blob;
    BOOST_CHECK_EQUAL(encoded.size(), Size);
    BOOST_CHECK_EQUAL(std::memcmp(encoded.data(), bytes.data(), Size), 0);

    CLegacyBLSBlob<Size> decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded == blob);
    BOOST_CHECK(encoded.empty());
}

BOOST_AUTO_TEST_CASE(byte_exact_round_trip)
{
    CheckOpaqueRoundTrip<CLegacyBLSPublicKey::SERIALIZED_SIZE>();
    CheckOpaqueRoundTrip<CLegacyBLSSignature::SERIALIZED_SIZE>();
}

BOOST_AUTO_TEST_CASE(null_and_malformed_fields)
{
    CLegacyBLSPublicKey key;
    BOOST_CHECK(key.IsNull());
    BOOST_CHECK(!key.IsValid());

    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> noncanonical{};
    noncanonical.front() = 0xff;
    BOOST_CHECK(key.SetBytes(noncanonical));
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(key.GetBytes() == noncanonical);

    const std::array<uint8_t, 1> wrong_size{1};
    BOOST_CHECK(!key.SetBytes(wrong_size));
    BOOST_CHECK(key.IsNull());
}

BOOST_AUTO_TEST_CASE(public_key_scheme_encoding_equivalence)
{
    // Mainnet ProUpReg dee303e3... at height 1,625,508 reserialized
    // this unchanged operator key from legacy v1 to basic v2.
    const auto legacy_bytes{ParseHex(
        "0171e2a623a3f2709cb7d1802860be86ed5f5ef78c09c166"
        "f3f58369e1bbd55b50a47f3ca5464819b21131026d678afb")};
    const auto basic_bytes{ParseHex(
        "8171e2a623a3f2709cb7d1802860be86ed5f5ef78c09c166"
        "f3f58369e1bbd55b50a47f3ca5464819b21131026d678afb")};
    CLegacyBLSPublicKey legacy_key;
    CLegacyBLSPublicKey basic_key;
    BOOST_REQUIRE(legacy_key.SetBytes(legacy_bytes));
    BOOST_REQUIRE(basic_key.SetBytes(basic_bytes));

    BOOST_CHECK(legacy_key != basic_key);
    BOOST_CHECK(AreLegacyBLSPublicKeyEncodingsEquivalent(
        legacy_key, /*lhs_legacy_encoding=*/true,
        basic_key, /*rhs_legacy_encoding=*/false));
    BOOST_CHECK(AreLegacyBLSPublicKeyEncodingsEquivalent(
        basic_key, /*lhs_legacy_encoding=*/false,
        legacy_key, /*rhs_legacy_encoding=*/true));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        legacy_key, /*lhs_legacy_encoding=*/true,
        basic_key, /*rhs_legacy_encoding=*/true));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        basic_key, /*lhs_legacy_encoding=*/true,
        basic_key, /*rhs_legacy_encoding=*/false));

    // Mainnet ProUpReg 5dd22837... at height 1,737,343 covers the
    // opposite sign-bit mapping.
    const auto signed_legacy_bytes{ParseHex(
        "92f5296c63839c6fdf7fb5dcf23dc3ababc750a32319240d"
        "fcf003b4402bb6c1b96d47fa301e8b617f5936e1c2b84c34")};
    const auto signed_basic_bytes{ParseHex(
        "b2f5296c63839c6fdf7fb5dcf23dc3ababc750a32319240d"
        "fcf003b4402bb6c1b96d47fa301e8b617f5936e1c2b84c34")};
    CLegacyBLSPublicKey signed_legacy_key;
    CLegacyBLSPublicKey signed_basic_key;
    BOOST_REQUIRE(signed_legacy_key.SetBytes(signed_legacy_bytes));
    BOOST_REQUIRE(signed_basic_key.SetBytes(signed_basic_bytes));
    BOOST_CHECK(AreLegacyBLSPublicKeyEncodingsEquivalent(
        signed_legacy_key, /*lhs_legacy_encoding=*/true,
        signed_basic_key, /*rhs_legacy_encoding=*/false));

    auto opposite_sign_bytes{basic_bytes};
    opposite_sign_bytes.front() ^= 0x20U;
    CLegacyBLSPublicKey opposite_sign_key;
    BOOST_REQUIRE(opposite_sign_key.SetBytes(opposite_sign_bytes));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        legacy_key, /*lhs_legacy_encoding=*/true,
        opposite_sign_key, /*rhs_legacy_encoding=*/false));

    CLegacyBLSPublicKey null_key;
    BOOST_CHECK(AreLegacyBLSPublicKeyEncodingsEquivalent(
        null_key, /*lhs_legacy_encoding=*/true,
        null_key, /*rhs_legacy_encoding=*/false));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        null_key, /*lhs_legacy_encoding=*/true,
        basic_key, /*rhs_legacy_encoding=*/false));

    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> infinity_bytes{};
    infinity_bytes.front() = 0xc0;
    CLegacyBLSPublicKey infinity_key;
    BOOST_REQUIRE(infinity_key.SetBytes(infinity_bytes));
    BOOST_CHECK(AreLegacyBLSPublicKeyEncodingsEquivalent(
        infinity_key, /*lhs_legacy_encoding=*/true,
        infinity_key, /*rhs_legacy_encoding=*/false));

    auto malformed_infinity_bytes{infinity_bytes};
    malformed_infinity_bytes.back() = 1;
    CLegacyBLSPublicKey malformed_infinity_key;
    BOOST_REQUIRE(malformed_infinity_key.SetBytes(malformed_infinity_bytes));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        infinity_key, /*lhs_legacy_encoding=*/true,
        malformed_infinity_key, /*rhs_legacy_encoding=*/false));

    auto changed_tail_bytes{basic_bytes};
    changed_tail_bytes.back() ^= 1U;
    CLegacyBLSPublicKey changed_tail_key;
    BOOST_REQUIRE(changed_tail_key.SetBytes(changed_tail_bytes));
    BOOST_CHECK(!AreLegacyBLSPublicKeyEncodingsEquivalent(
        legacy_key, /*lhs_legacy_encoding=*/true,
        changed_tail_key, /*rhs_legacy_encoding=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
