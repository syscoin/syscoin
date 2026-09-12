// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/legacy_quorum_commitment.h>

namespace llmq::legacy {

bool FinalCommitment::IsNull() const noexcept
{
    return CountSigners() == 0 && CountValidMembers() == 0 &&
           quorum_public_key.IsNull() && quorum_vvec_hash.IsNull() &&
           quorum_signature.IsNull() && members_signature.IsNull();
}

bool FinalCommitment::HasExpectedSize(std::size_t expected_size) const noexcept
{
    return expected_size <= MAX_QUORUM_MEMBERS &&
           signers.size() == expected_size && valid_members.size() == expected_size;
}

bool FinalCommitment::IsStructurallyValid(
    std::size_t expected_size,
    std::size_t actual_member_count,
    std::size_t minimum_signers,
    uint16_t expected_version) const noexcept
{
    if (quorum_hash.IsNull() || !HasExpectedSize(expected_size)) {
        return false;
    }

    // Historical null commitments intentionally bypassed the BLS-version and
    // member-count checks after their quorum hash and fixed bitset sizes were
    // established. Preserve that accepted byte language exactly through H.
    if (IsNull()) return true;
    if (version != expected_version ||
        (version != LEGACY_SCHEME_COMMITMENT_VERSION &&
         version != BASIC_SCHEME_COMMITMENT_VERSION) ||
        actual_member_count > expected_size || minimum_signers > actual_member_count) {
        return false;
    }
    if (static_cast<std::size_t>(CountSigners()) < minimum_signers ||
        static_cast<std::size_t>(CountValidMembers()) < minimum_signers ||
        quorum_public_key.IsNull() || quorum_vvec_hash.IsNull() ||
        quorum_signature.IsNull() || members_signature.IsNull()) {
        return false;
    }
    for (std::size_t index{actual_member_count}; index < expected_size; ++index) {
        if (signers[index] || valid_members[index]) return false;
    }
    return true;
}

uint256 BuildCommitmentHash(
    const uint256& block_hash,
    const std::vector<bool>& valid_members,
    const CLegacyBLSPublicKey& public_key,
    const uint256& vvec_hash)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer << block_hash
           << Using<BoundedDynamicBitSetFormatter<MAX_QUORUM_MEMBERS>>(
                  valid_members)
           << public_key << vvec_hash;
    return writer.GetHash();
}

} // namespace llmq::legacy
