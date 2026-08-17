// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_LLMQ_QUORUMS_COMMITMENT_H
#define SYSCOIN_LLMQ_QUORUMS_COMMITMENT_H

#include <llmq/legacy_quorum_commitment.h>
#include <primitives/transaction.h>

#include <univalue.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

class CBlockIndex;

namespace llmq {

/**
 * Compatibility view of a historical on-chain DKG commitment. Cryptographic
 * fields are opaque bytes; this type can decode the anchored prefix but cannot
 * verify or create a BLS signature.
 */
class CFinalCommitment {
public:
    static constexpr uint16_t LEGACY_BLS_NON_INDEXED_QUORUM_VERSION =
        legacy::LEGACY_SCHEME_COMMITMENT_VERSION;
    static constexpr uint16_t BASIC_BLS_NON_INDEXED_QUORUM_VERSION =
        legacy::BASIC_SCHEME_COMMITMENT_VERSION;

    uint16_t nVersion{LEGACY_BLS_NON_INDEXED_QUORUM_VERSION};
    uint256 quorumHash;
    std::vector<bool> signers;
    std::vector<bool> validMembers;
    CLegacyBLSPublicKey quorumPublicKey;
    uint256 quorumVvecHash;
    CLegacyBLSSignature quorumSig;
    CLegacyBLSSignature membersSig;

    CFinalCommitment() = default;
    explicit CFinalCommitment(const uint256& quorum_hash);

    [[nodiscard]] int CountSigners() const noexcept
    {
        return static_cast<int>(std::count(signers.begin(), signers.end(), true));
    }
    [[nodiscard]] int CountValidMembers() const noexcept
    {
        return static_cast<int>(
            std::count(validMembers.begin(), validMembers.end(), true));
    }
    [[nodiscard]] bool IsNull() const noexcept;
    [[nodiscard]] bool VerifyNull() const noexcept;
    [[nodiscard]] bool VerifySizes() const noexcept;
    [[nodiscard]] bool IsStructurallyValid(
        std::size_t expected_size,
        std::size_t actual_member_count,
        std::size_t minimum_signers,
        uint16_t expected_version) const;

    /** Structural replay only. check_sigs is accepted for source compatibility. */
    [[nodiscard]] bool Verify(const CBlockIndex* quorum_base,
                              bool check_sigs) const;

    [[nodiscard]] static constexpr uint16_t GetVersion(bool basic_scheme)
    {
        return basic_scheme ? BASIC_BLS_NON_INDEXED_QUORUM_VERSION
                            : LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
    }

    SERIALIZE_METHODS(CFinalCommitment, obj)
    {
        READWRITE(obj.nVersion, obj.quorumHash);
        READWRITE(
            Using<legacy::BoundedDynamicBitSetFormatter<
                legacy::MAX_QUORUM_MEMBERS>>(obj.signers),
            Using<legacy::BoundedDynamicBitSetFormatter<
                legacy::MAX_QUORUM_MEMBERS>>(obj.validMembers),
            obj.quorumPublicKey,
            obj.quorumVvecHash,
            obj.quorumSig,
            obj.membersSig);
    }

    void ToJson(UniValue& object) const;
};

using CFinalCommitmentPtr = std::unique_ptr<CFinalCommitment>;

class CFinalCommitmentTxPayload {
public:
    static constexpr uint16_t CURRENT_VERSION =
        legacy::FINAL_COMMITMENT_PAYLOAD_VERSION;

    uint16_t nVersion{CURRENT_VERSION};
    uint32_t nHeight{0};
    CFinalCommitment commitment;

    SERIALIZE_METHODS(CFinalCommitmentTxPayload, obj)
    {
        READWRITE(obj.nVersion, obj.nHeight, obj.commitment);
    }

    void ToJson(UniValue& object) const;
    [[nodiscard]] bool IsNull() const noexcept { return nHeight == 0; }
};

[[nodiscard]] uint256 BuildCommitmentHash(
    const uint256& block_hash,
    const std::vector<bool>& valid_members,
    const CLegacyBLSPublicKey& public_key,
    const uint256& vvec_hash);

} // namespace llmq

#endif // SYSCOIN_LLMQ_QUORUMS_COMMITMENT_H
