// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_PQ_VOTING_KEY_H
#define SYSCOIN_EVO_PQ_VOTING_KEY_H

#include <llmq/pq_chainlock_types.h>
#include <span.h>

#include <algorithm>
#include <cstdint>
#include <ios>
#include <limits>
#include <string_view>

namespace llmq::pq {

[[nodiscard]] inline bool IsNullVotingPublicKey(const GlobalPublicKey& public_key) noexcept
{
    return std::all_of(public_key.begin(), public_key.end(),
                       [](uint8_t byte) { return byte == 0; });
}

/** Owner-delegated funding authority, independent of the operator key lifecycle. */
struct VotingKeyRecord {
    GlobalPublicKey public_key{};
    uint32_t key_version{0};
    int32_t activated_height{-1};

    [[nodiscard]] bool IsStructurallyValid() const noexcept
    {
        return key_version == 0
            ? activated_height == -1 && IsNullVotingPublicKey(public_key)
            : activated_height >= 0;
    }

    [[nodiscard]] bool HasActiveKey() const noexcept
    {
        return IsStructurallyValid() && key_version != 0 &&
               !IsNullVotingPublicKey(public_key);
    }

    [[nodiscard]] bool UpdatePublicKey(const GlobalPublicKey& next_key,
                                      int32_t height) noexcept
    {
        if (!IsStructurallyValid() || height < 0) return false;
        if (public_key == next_key) return true;
        if (key_version == std::numeric_limits<uint32_t>::max()) return false;
        public_key = next_key;
        ++key_version;
        activated_height = height;
        return true;
    }

    SERIALIZE_METHODS(VotingKeyRecord, obj)
    {
        SER_WRITE(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ voting-key record");
        });
        READWRITE(obj.public_key, obj.key_version, obj.activated_height);
        SER_READ(obj, if (!obj.IsStructurallyValid()) {
            throw std::ios_base::failure("non-canonical PQ voting-key record");
        });
    }

    friend bool operator==(const VotingKeyRecord&, const VotingKeyRecord&) = default;
};

template <typename Stream>
void SerializeVotingKeyCommitment(Stream& stream, const VotingKeyRecord& record)
{
    if (!record.IsStructurallyValid()) {
        throw std::ios_base::failure("non-canonical PQ voting-key commitment");
    }
    // Empty historical records must not change pre-PQ branch commitments.
    if (record.key_version == 0) return;
    constexpr std::string_view domain{"SYS_PQ_DMN_VOTING_KEY_V1"};
    stream.write(AsBytes(Span{domain.data(), domain.size()}));
    stream << record;
}

} // namespace llmq::pq

#endif // SYSCOIN_EVO_PQ_VOTING_KEY_H
