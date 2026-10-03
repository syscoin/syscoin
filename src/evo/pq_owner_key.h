// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_OWNER_KEY_H
#define SYSCOIN_EVO_PQ_OWNER_KEY_H

#include <llmq/pq_chainlock_types.h>
#include <span.h>

#include <algorithm>
#include <cstdint>
#include <ios>
#include <limits>
#include <string_view>

namespace llmq::pq {

inline constexpr std::string_view PQ_OWNER_UPDATE_CONTEXT{"SYS_PQ_OWNER_UPDATE_V1"};
inline constexpr std::string_view PQ_OWNER_PROOF_CONTEXT{"SYS_PQ_OWNER_PROOF_V1"};
inline constexpr std::string_view PQ_GLOBAL_OWNER_REGISTER_CONTEXT{"SYS_PQ_GLOBAL_OWNER_REGISTER_V2"};

[[nodiscard]] inline bool IsNullOwnerPublicKey(const GlobalPublicKey& public_key) noexcept
{
    return std::all_of(public_key.begin(), public_key.end(), [](uint8_t byte) { return byte == 0; });
}

/** Optional one-way replacement of the legacy owner, independent of voting/operator keys. */
struct OwnerKeyRecord {
    GlobalPublicKey public_key{};
    uint32_t key_version{0};
    int32_t activated_height{-1};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return key_version == 0
            ? activated_height == -1 && IsNullOwnerPublicKey(public_key)
            : activated_height >= 0 && !IsNullOwnerPublicKey(public_key);
    }
    [[nodiscard]] bool HasActiveKey() const noexcept
    {
        return key_version != 0 && IsStructurallyValid();
    }
    [[nodiscard]] bool UpdatePublicKey(const GlobalPublicKey& next_key, int32_t height) noexcept
    {
        if (!IsStructurallyValid() || height < 0 || IsNullOwnerPublicKey(next_key)) return false;
        if (public_key == next_key) return true;
        if (key_version == std::numeric_limits<uint32_t>::max()) return false;
        public_key = next_key;
        ++key_version;
        activated_height = height;
        return true;
    }
    SERIALIZE_METHODS(OwnerKeyRecord, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ owner-key record");
        });
        READWRITE(obj.public_key, obj.key_version, obj.activated_height);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ owner-key record");
        });
    }
    friend bool operator==(const OwnerKeyRecord&, const OwnerKeyRecord&) = default;
};

template <typename Stream>
void SerializeOwnerKeyCommitment(Stream& stream, const OwnerKeyRecord& record)
{
    if (!record.IsStructurallyValid()) throw std::ios_base::failure("non-canonical PQ owner-key commitment");
    // Historical states retain their exact commitments before opt-in enrollment.
    if (record.key_version == 0) return;
    constexpr std::string_view domain{"SYS_PQ_DMN_OWNER_KEY_V1"};
    stream.write(AsBytes(Span{domain.data(), domain.size()}));
    stream << record;
}

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_OWNER_KEY_H
