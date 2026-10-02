// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pqkey.h>

#include <hash.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>

namespace wallet {
namespace {

constexpr std::string_view PREFIX{"syspqkey1:"};
constexpr std::string_view HEX_DIGITS{"0123456789abcdef"};
constexpr std::array<unsigned char, 4> MAGIC{'S', 'P', 'Q', 'K'};
constexpr unsigned char FORMAT_VERSION{1};
constexpr unsigned char ALGORITHM_SLH_DSA_SHAKE_128S{1};
constexpr uint8_t VALID_ROLES{static_cast<uint8_t>(PQKeyRole::VOTING) |
                              static_cast<uint8_t>(PQKeyRole::OWNER)};
constexpr size_t HEADER_SIZE{MAGIC.size() + 3};
constexpr size_t PAYLOAD_SIZE{HEADER_SIZE + slhdsa::PUBLIC_KEY_SIZE + slhdsa::SECRET_KEY_SIZE};
constexpr size_t CHECKED_SIZE{PAYLOAD_SIZE + 4};
constexpr size_t ENCODED_SIZE{PREFIX.size() + CHECKED_SIZE * 2};

bool IsValidRecord(const PQKeyExport& record)
{
    if (record.roles == 0 || (record.roles & ~VALID_ROLES) != 0 ||
        record.secret.size() != slhdsa::SECRET_KEY_SIZE) return false;
    const auto key{slhdsa::ImportSecretKey(record.secret)};
    slhdsa::PublicKey derived{};
    return key && key->GetPublicKey(derived) && derived == record.public_key;
}

} // namespace

std::optional<std::string> EncodePQKey(const PQKeyExport& record, std::string& error)
{
    if (!IsValidRecord(record)) {
        error = "Invalid PQ key record";
        return std::nullopt;
    }
    CKeyingMaterial payload;
    payload.reserve(CHECKED_SIZE);
    payload.insert(payload.end(), MAGIC.begin(), MAGIC.end());
    payload.push_back(FORMAT_VERSION);
    payload.push_back(ALGORITHM_SLH_DSA_SHAKE_128S);
    payload.push_back(record.roles);
    payload.insert(payload.end(), record.public_key.begin(), record.public_key.end());
    payload.insert(payload.end(), record.secret.begin(), record.secret.end());
    const uint256 checksum{Hash(Span{payload})};
    // The secure buffer also owns the checksum suffix. No ordinary temporary
    // vector contains secret bytes; only the explicit export string is public
    // memory, as required for returning it over RPC.
    payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
    std::string encoded;
    encoded.reserve(ENCODED_SIZE);
    encoded.append(PREFIX);
    for (const unsigned char byte : payload) {
        encoded.push_back(HEX_DIGITS[byte >> 4]);
        encoded.push_back(HEX_DIGITS[byte & 15]);
    }
    error.clear();
    return encoded;
}

std::optional<PQKeyExport> DecodePQKey(std::string_view encoded, std::string& error)
{
    error = "Invalid PQ key encoding";
    // Reject unbounded input and foreign formats before allocating. Decode
    // directly into locked, cleansing storage instead of a ParseHex vector.
    if (!encoded.starts_with(PREFIX) || encoded.size() != ENCODED_SIZE) return std::nullopt;
    encoded.remove_prefix(PREFIX.size());
    CKeyingMaterial checked(CHECKED_SIZE, 0);
    for (size_t i{0}; i < CHECKED_SIZE; ++i) {
        const int high{HexDigit(encoded[2 * i])};
        const int low{HexDigit(encoded[2 * i + 1])};
        if (high < 0 || low < 0) return std::nullopt;
        checked[i] = (high << 4) | low;
    }
    const uint256 checksum{Hash(Span{checked}.first(PAYLOAD_SIZE))};
    if (!std::equal(checksum.begin(), checksum.begin() + 4, checked.begin() + PAYLOAD_SIZE) ||
        !std::equal(MAGIC.begin(), MAGIC.end(), checked.begin()) ||
        checked[MAGIC.size()] != FORMAT_VERSION ||
        checked[MAGIC.size() + 1] != ALGORITHM_SLH_DSA_SHAKE_128S) return std::nullopt;

    PQKeyExport record;
    record.roles = checked[MAGIC.size() + 2];
    std::copy_n(checked.begin() + HEADER_SIZE, record.public_key.size(), record.public_key.begin());
    record.secret.assign(checked.begin() + HEADER_SIZE + record.public_key.size(),
                         checked.begin() + PAYLOAD_SIZE);
    if (!IsValidRecord(record)) return std::nullopt;
    error.clear();
    return record;
}

} // namespace wallet
