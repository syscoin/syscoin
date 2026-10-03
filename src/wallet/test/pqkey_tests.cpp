// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pqkey.h>

#include <hash.h>
#include <span.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace wallet {
namespace {

constexpr std::string_view PREFIX{"syspqkey1:"};
constexpr std::string_view KNOWN_RECORD{
    "syspqkey1:5350514b010103"
    "202122232425262728292a2b2c2d2e2f89fd81fdbb5b94129b14761bdc6bf682"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f89fd81fdbb5b94129b14761bdc6bf682"
    "0ccfe2d6"};

PQKeyExport KnownKey()
{
    // Same published deterministic seed/root as the SLH-DSA known-answer test.
    constexpr std::array<unsigned char, 16> root{
        0x89, 0xfd, 0x81, 0xfd, 0xbb, 0x5b, 0x94, 0x12,
        0x9b, 0x14, 0x76, 0x1b, 0xdc, 0x6b, 0xf6, 0x82};
    PQKeyExport result;
    result.roles = 3;
    result.secret.resize(slhdsa::SECRET_KEY_SIZE);
    for (size_t i{0}; i < 48; ++i) result.secret[i] = i;
    std::copy(root.begin(), root.end(), result.secret.begin() + 48);
    std::copy_n(result.secret.begin() + 32, result.public_key.size(), result.public_key.begin());
    return result;
}

std::string ChangePayloadByte(size_t index, unsigned char value)
{
    constexpr std::string_view digits{"0123456789abcdef"};
    std::string result{KNOWN_RECORD};
    const size_t offset{PREFIX.size() + 2 * index};
    result[offset] = digits[value >> 4];
    result[offset + 1] = digits[value & 15];
    CKeyingMaterial payload(103, 0);
    for (size_t i{0}; i < payload.size(); ++i) {
        payload[i] = (HexDigit(result[PREFIX.size() + 2 * i]) << 4) |
            HexDigit(result[PREFIX.size() + 2 * i + 1]);
    }
    const auto checksum{Hash(Span{payload})};
    result.replace(PREFIX.size() + 2 * payload.size(), 8,
                   HexStr(Span{checksum}.first(4)));
    return result;
}

} // namespace

BOOST_AUTO_TEST_SUITE(wallet_pqkey_tests)

BOOST_AUTO_TEST_CASE(portable_key_known_encoding_and_all_roles)
{
    auto original{KnownKey()};
    std::string error{"stale error"};
    const auto known_encoded{EncodePQKey(original, error)};
    BOOST_REQUIRE(known_encoded);
    BOOST_CHECK_EQUAL(*known_encoded, KNOWN_RECORD);
    BOOST_CHECK(error.empty());

    for (uint8_t roles{1}; roles <= 3; ++roles) {
        original.roles = roles;
        const auto encoded{EncodePQKey(original, error)};
        BOOST_REQUIRE(encoded);
        BOOST_CHECK_EQUAL(encoded->size(), PREFIX.size() + 214);
        error = "stale error";
        const auto decoded{DecodePQKey(*encoded, error)};
        BOOST_REQUIRE(decoded);
        BOOST_CHECK(error.empty());
        BOOST_CHECK(decoded->public_key == original.public_key);
        BOOST_CHECK(decoded->secret == original.secret);
        BOOST_CHECK_EQUAL(decoded->roles, roles);
    }

    // Hex case is irrelevant; export always produces the canonical lower case.
    std::string uppercase{KNOWN_RECORD};
    std::transform(uppercase.begin() + PREFIX.size(), uppercase.end(),
        uppercase.begin() + PREFIX.size(), [](char c) { return c >= 'a' && c <= 'f' ? c - 'a' + 'A' : c; });
    const auto decoded{DecodePQKey(uppercase, error)};
    BOOST_REQUIRE(decoded);
    const auto encoded{EncodePQKey(*decoded, error)};
    BOOST_REQUIRE(encoded);
    BOOST_CHECK_EQUAL(*encoded, KNOWN_RECORD);
}

BOOST_AUTO_TEST_CASE(portable_key_rejects_malformed_text_and_checksum)
{
    std::string error;
    const auto reject = [&](std::string_view text) {
        error.clear();
        BOOST_CHECK(!DecodePQKey(text, error));
        BOOST_CHECK(!error.empty());
    };
    reject("");
    reject("syspqkey1:");
    reject(std::string(1'000'000, 'a'));
    reject(KNOWN_RECORD.substr(0, KNOWN_RECORD.size() - 1));
    reject(std::string{KNOWN_RECORD} + "0");
    reject(" " + std::string{KNOWN_RECORD});
    reject(std::string{KNOWN_RECORD} + "\n");
    for (const char replacement : {' ', 'g', '\0'}) {
        std::string malformed{KNOWN_RECORD};
        malformed[PREFIX.size() + 14] = replacement;
        reject(malformed);
    }
    std::string foreign_prefix{KNOWN_RECORD};
    foreign_prefix[8] = '2';
    reject(foreign_prefix);
    std::string bad_checksum{KNOWN_RECORD};
    bad_checksum.back() = bad_checksum.back() == '0' ? '1' : '0';
    reject(bad_checksum);
}

BOOST_AUTO_TEST_CASE(portable_key_rejects_rechecksummed_unsupported_or_corrupt_records)
{
    std::string error;
    // A valid checksum never permits foreign magic, formats, algorithms,
    // invalid role bits, mismatched public keys, or inconsistent secret roots.
    for (const auto [offset, replacement] : std::array<std::pair<size_t, unsigned char>, 8>{{
             {0, 'X'}, {4, 2}, {5, 2}, {6, 0}, {6, 4}, {7, 0}, {39, 1}, {102, 0}}}) {
        BOOST_CHECK(!DecodePQKey(ChangePayloadByte(offset, replacement), error));
        BOOST_CHECK(!error.empty());
    }
}

BOOST_AUTO_TEST_CASE(portable_key_export_rejects_invalid_records)
{
    const auto valid{KnownKey()};
    std::string error;
    for (const uint8_t roles : {0, 4, 255}) {
        auto invalid{valid};
        invalid.roles = roles;
        BOOST_CHECK(!EncodePQKey(invalid, error));
    }
    auto invalid{valid};
    invalid.secret.pop_back();
    BOOST_CHECK(!EncodePQKey(invalid, error));
    invalid = valid;
    invalid.secret.push_back(0);
    BOOST_CHECK(!EncodePQKey(invalid, error));
    invalid = valid;
    invalid.public_key[0] ^= 1;
    BOOST_CHECK(!EncodePQKey(invalid, error));
    invalid = valid;
    invalid.secret.back() ^= 1;
    BOOST_CHECK(!EncodePQKey(invalid, error));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
