// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NEVM_RESPONSE_H
#define SYSCOIN_NEVM_RESPONSE_H

#include <uint256.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

/** The immutable pair identified by an explicit NEVM validation rejection. */
struct NEVMBlockReject {
    uint256 nevm_hash;
    uint256 syscoin_hash;
};

/** Accept only the complete canonical token, never an embedded error message. */
inline std::optional<NEVMBlockReject> ParseNEVMBlockReject(std::string_view response)
{
    constexpr std::string_view prefix{"invalid:"};
    constexpr std::size_t hash_size{64};
    constexpr std::size_t separator{prefix.size() + hash_size};
    if (response.size() != separator + 1 + hash_size ||
        response.substr(0, prefix.size()) != prefix || response[separator] != ':') {
        return std::nullopt;
    }
    const auto nevm_hash = response.substr(prefix.size(), hash_size);
    const auto syscoin_hash = response.substr(separator + 1, hash_size);
    const auto lowercase_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    };
    if (!std::all_of(nevm_hash.begin(), nevm_hash.end(), lowercase_hex) ||
        !std::all_of(syscoin_hash.begin(), syscoin_hash.end(), lowercase_hex)) {
        return std::nullopt;
    }
    // SetHex consumes display order. Validate first because it also accepts
    // partial input, uppercase digits, whitespace and optional 0x prefixes.
    return NEVMBlockReject{uint256S(std::string{nevm_hash}), uint256S(std::string{syscoin_hash})};
}

#endif // SYSCOIN_NEVM_RESPONSE_H
