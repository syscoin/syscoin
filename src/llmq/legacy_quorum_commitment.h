// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_LEGACY_QUORUM_COMMITMENT_H
#define SYSCOIN_LLMQ_LEGACY_QUORUM_COMMITMENT_H

#include <crypto/legacy_bls.h>
#include <hash.h>
#include <serialize.h>
#include <uint256.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <vector>

namespace llmq::legacy {

inline constexpr std::size_t MAX_QUORUM_MEMBERS{400};
inline constexpr uint16_t LEGACY_SCHEME_COMMITMENT_VERSION{1};
inline constexpr uint16_t BASIC_SCHEME_COMMITMENT_VERSION{3};
inline constexpr uint16_t FINAL_COMMITMENT_PAYLOAD_VERSION{2};

/**
 * Byte-identical DynamicBitSet codec with a bound checked before allocation.
 * The historical format stores a CompactSize bit count followed by packed
 * least-significant-bit-first bytes.
 */
template <std::size_t MaxBits>
struct BoundedDynamicBitSetFormatter {
    template <typename Stream>
    void Ser(Stream& stream, const std::vector<bool>& bits) const
    {
        if (bits.size() > MaxBits) {
            throw std::ios_base::failure("legacy quorum bitset exceeds bound");
        }
        WriteCompactSize(stream, bits.size());
        WriteFixedBitSet(stream, bits, bits.size());
    }

    template <typename Stream>
    void Unser(Stream& stream, std::vector<bool>& bits) const
    {
        const uint64_t size{ReadCompactSize(stream)};
        if (size > MaxBits) {
            throw std::ios_base::failure("legacy quorum bitset exceeds bound");
        }
        ReadFixedBitSet(stream, bits, static_cast<std::size_t>(size));
    }
};

/**
 * Historical on-chain DKG result. BLS-shaped fields are deliberately opaque:
 * this type exists only to reconstruct deterministic state committed by
 * pre-activation history.
 */
struct FinalCommitment {
    uint16_t version{LEGACY_SCHEME_COMMITMENT_VERSION};
    uint256 quorum_hash;
    std::vector<bool> signers;
    std::vector<bool> valid_members;
    CLegacyBLSPublicKey quorum_public_key;
    uint256 quorum_vvec_hash;
    CLegacyBLSSignature quorum_signature;
    CLegacyBLSSignature members_signature;

    SERIALIZE_METHODS(FinalCommitment, obj)
    {
        READWRITE(obj.version, obj.quorum_hash);
        READWRITE(
            Using<BoundedDynamicBitSetFormatter<MAX_QUORUM_MEMBERS>>(obj.signers),
            Using<BoundedDynamicBitSetFormatter<MAX_QUORUM_MEMBERS>>(obj.valid_members),
            obj.quorum_public_key,
            obj.quorum_vvec_hash,
            obj.quorum_signature,
            obj.members_signature);
    }

    [[nodiscard]] int CountSigners() const noexcept
    {
        return static_cast<int>(std::count(signers.begin(), signers.end(), true));
    }
    [[nodiscard]] int CountValidMembers() const noexcept
    {
        return static_cast<int>(
            std::count(valid_members.begin(), valid_members.end(), true));
    }
    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool HasExpectedSize(std::size_t expected_size) const noexcept;
    [[nodiscard]] bool IsStructurallyValid(
        std::size_t expected_size,
        std::size_t actual_member_count,
        std::size_t minimum_signers,
        uint16_t expected_version) const noexcept;

    friend bool operator==(const FinalCommitment&, const FinalCommitment&) = default;
};

struct FinalCommitmentTxPayload {
    uint16_t version{FINAL_COMMITMENT_PAYLOAD_VERSION};
    uint32_t height{0};
    FinalCommitment commitment;

    SERIALIZE_METHODS(FinalCommitmentTxPayload, obj)
    {
        READWRITE(obj.version, obj.height, obj.commitment);
    }

    [[nodiscard]] bool IsNull() const noexcept { return height == 0; }
    friend bool operator==(const FinalCommitmentTxPayload&,
                           const FinalCommitmentTxPayload&) = default;
};

/** Reproduce the exact historical commitment digest without a BLS library. */
[[nodiscard]] uint256 BuildCommitmentHash(
    const uint256& block_hash,
    const std::vector<bool>& valid_members,
    const CLegacyBLSPublicKey& public_key,
    const uint256& vvec_hash);

} // namespace llmq::legacy

#endif // SYSCOIN_LLMQ_LEGACY_QUORUM_COMMITMENT_H
