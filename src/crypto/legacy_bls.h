// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CRYPTO_LEGACY_BLS_H
#define SYSCOIN_CRYPTO_LEGACY_BLS_H

#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

/**
 * Opaque storage for BLS fields committed before the post-quantum activation
 * height. These bytes are retained solely so historical consensus objects and
 * deterministic-masternode state remain byte-for-byte decodable. No group
 * element is constructed and no cryptographic validity is implied.
 */
template <size_t Size>
class CLegacyBLSBlob
{
private:
    std::array<uint8_t, Size> m_bytes{};

public:
    static constexpr size_t SERIALIZED_SIZE{Size};

    CLegacyBLSBlob() = default;
    explicit CLegacyBLSBlob(Span<const uint8_t> bytes) { SetBytes(bytes); }

    bool operator==(const CLegacyBLSBlob&) const = default;
    bool operator!=(const CLegacyBLSBlob&) const = default;
    bool operator<(const CLegacyBLSBlob& other) const { return m_bytes < other.m_bytes; }

    [[nodiscard]] bool IsNull() const
    {
        return std::all_of(m_bytes.begin(), m_bytes.end(), [](uint8_t byte) { return byte == 0; });
    }

    [[nodiscard]] bool IsValid() const { return !IsNull(); }

    void SetNull() { m_bytes.fill(0); }

    bool SetBytes(Span<const uint8_t> bytes)
    {
        if (bytes.size() != Size) {
            SetNull();
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), m_bytes.begin());
        return true;
    }

    [[nodiscard]] const std::array<uint8_t, Size>& GetBytes() const { return m_bytes; }
    [[nodiscard]] std::string ToString() const { return HexStr(m_bytes); }

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        stream.write(AsBytes(Span{m_bytes}));
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream.read(AsWritableBytes(Span{m_bytes}));
    }
};

using CLegacyBLSPublicKey = CLegacyBLSBlob<48>;
using CLegacyBLSSignature = CLegacyBLSBlob<96>;

/**
 * Reproduce the released lazy-public-key comparison across the legacy and
 * basic G1 serialization schemes without constructing a BLS group element.
 * Historical provider transactions were accepted by released validation and
 * are fixed by the canonical chain; this helper only preserves their encoding
 * equivalence during opaque replay.
 */
[[nodiscard]] inline bool AreLegacyBLSPublicKeyEncodingsEquivalent(
    const CLegacyBLSPublicKey& lhs,
    bool lhs_legacy_encoding,
    const CLegacyBLSPublicKey& rhs,
    bool rhs_legacy_encoding)
{
    if (lhs_legacy_encoding == rhs_legacy_encoding) return lhs == rhs;

    const auto& legacy{lhs_legacy_encoding ? lhs.GetBytes() : rhs.GetBytes()};
    const auto& basic{lhs_legacy_encoding ? rhs.GetBytes() : lhs.GetBytes()};

    if (std::all_of(legacy.begin(), legacy.end(), [](uint8_t byte) { return byte == 0; }) ||
        std::all_of(basic.begin(), basic.end(), [](uint8_t byte) { return byte == 0; })) {
        return legacy == basic;
    }

    const auto is_canonical_infinity = [](const auto& bytes) {
        return bytes.front() == 0xc0 &&
               std::all_of(bytes.begin() + 1, bytes.end(), [](uint8_t byte) { return byte == 0; });
    };
    const bool legacy_infinity{is_canonical_infinity(legacy)};
    const bool basic_infinity{is_canonical_infinity(basic)};
    if (legacy_infinity || basic_infinity) return legacy_infinity && basic_infinity;

    // Legacy encodes the sign in bit 7. Basic requires the compression bit in
    // bit 7 and moves the sign to bit 5; the remaining x-coordinate is exact.
    if ((legacy.front() & 0x60U) != 0 ||
        (basic.front() & 0xc0U) != 0x80U) {
        return false;
    }
    const bool zero_x{
        (legacy.front() & 0x1fU) == 0 &&
        std::all_of(legacy.begin() + 1, legacy.end(), [](uint8_t byte) { return byte == 0; })};
    if (zero_x) return false;

    auto expected_basic{legacy};
    expected_basic.front() = static_cast<uint8_t>(
        0x80U | (legacy.front() & 0x1fU) |
        ((legacy.front() & 0x80U) != 0 ? 0x20U : 0U));
    return expected_basic == basic;
}

#endif // SYSCOIN_CRYPTO_LEGACY_BLS_H
