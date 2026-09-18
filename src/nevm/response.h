// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NEVM_RESPONSE_H
#define SYSCOIN_NEVM_RESPONSE_H

#include <uint256.h>
#include <crypto/sha256.h>
#include <serialize.h>
#include <span.h>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

/** The immutable pair identified by an explicit NEVM validation rejection. */
struct NEVMBlockReject {
    uint256 nevm_hash;
    uint256 syscoin_hash;
    std::optional<uint256> payload_hash{};

    bool IsPayload() const { return payload_hash.has_value(); }
    bool operator==(const NEVMBlockReject&) const = default;
    SERIALIZE_METHODS(NEVMBlockReject, obj)
    {
        bool has_payload{obj.payload_hash.has_value()};
        READWRITE(obj.nevm_hash, obj.syscoin_hash, has_payload);
        if (has_payload) {
            uint256 payload{obj.payload_hash.value_or(uint256{})};
            READWRITE(payload);
            SER_READ(obj, obj.payload_hash = payload);
        } else {
            SER_READ(obj, obj.payload_hash.reset());
        }
    }
};

/** One locally authorized attempt to replace an explicitly rejected payload. */
struct NEVMPayloadRepairRequest {
    uint64_t generation;
    NEVMBlockReject rejection;
    bool operator==(const NEVMPayloadRepairRequest&) const = default;
};

/** Recovery-only digest of the exact engine input, in wire byte order. */
inline uint256 NEVMPayloadFingerprint(const uint256& nevm_hash,
                                      const uint256& tx_root,
                                      const uint256& receipt_root,
                                      const uint256& syscoin_hash,
                                      Span<const uint8_t> payload)
{
    constexpr char domain[]{"syscoin-nevm-payload-v1"};
    uint256 result;
    CSHA256().Write(reinterpret_cast<const uint8_t*>(domain), sizeof(domain))
        .Write(nevm_hash.begin(), 32).Write(tx_root.begin(), 32)
        .Write(receipt_root.begin(), 32).Write(syscoin_hash.begin(), 32)
        .Write(payload.data(), payload.size()).Finalize(result.begin());
    return result;
}

/** Accept only the complete canonical token, never an embedded error message. */
inline std::optional<NEVMBlockReject> ParseNEVMBlockReject(std::string_view response)
{
    const bool payload{response.starts_with("payload-invalid:")};
    const std::string_view prefix{payload ? "payload-invalid:" : "invalid:"};
    constexpr std::size_t hash_size{64};
    const std::size_t separator{prefix.size() + hash_size};
    const std::size_t pair_end{separator + 1 + hash_size};
    if (response.size() != pair_end + (payload ? 1 + hash_size : 0) ||
        response.substr(0, prefix.size()) != prefix || response[separator] != ':') {
        return std::nullopt;
    }
    const auto nevm_hash = response.substr(prefix.size(), hash_size);
    const auto syscoin_hash = response.substr(separator + 1, hash_size);
    const auto payload_hash = payload ? response.substr(pair_end + 1) : std::string_view{};
    const auto lowercase_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    };
    if (!std::all_of(nevm_hash.begin(), nevm_hash.end(), lowercase_hex) ||
        !std::all_of(syscoin_hash.begin(), syscoin_hash.end(), lowercase_hex) ||
        (payload && (response[pair_end] != ':' ||
                     !std::all_of(payload_hash.begin(), payload_hash.end(), lowercase_hex)))) {
        return std::nullopt;
    }
    // SetHex consumes display order. Validate first because it also accepts
    // partial input, uppercase digits, whitespace and optional 0x prefixes.
    return NEVMBlockReject{uint256S(std::string{nevm_hash}), uint256S(std::string{syscoin_hash}),
        payload ? std::make_optional(uint256S(std::string{payload_hash})) : std::nullopt};
}

#endif // SYSCOIN_NEVM_RESPONSE_H
