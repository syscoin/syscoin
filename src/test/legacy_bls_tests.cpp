// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/legacy_bls.h>

#include <clientversion.h>
#include <streams.h>

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

BOOST_AUTO_TEST_SUITE_END()
