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
 * anchor. These bytes are retained solely so historical consensus objects and
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
    void Reset() { SetNull(); }

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
    [[nodiscard]] uint256 GetHash() const { return ::SerializeHash(*this); }
    [[nodiscard]] const CLegacyBLSBlob& Get() const { return *this; }
    [[nodiscard]] std::string ToString() const { return HexStr(m_bytes); }

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        stream.write(AsBytes(Span{m_bytes}));
    }

    template <typename Stream>
    void Serialize(Stream& stream, bool) const
    {
        Serialize(stream);
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        stream.read(AsWritableBytes(Span{m_bytes}));
    }

    void SetLegacy(bool) {}
};

using CLegacyBLSPublicKey = CLegacyBLSBlob<48>;
using CLegacyBLSSignature = CLegacyBLSBlob<96>;

#endif // SYSCOIN_CRYPTO_LEGACY_BLS_H
