// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_commitment.h>

#include <chain.h>
#include <chainparams.h>
#include <evo/deterministicmns.h>
#include <llmq/quorums_utils.h>

namespace llmq {

CFinalCommitment::CFinalCommitment(const uint256& quorum_hash)
    : quorumHash{quorum_hash}
{
    const int configured_size{
        Params().GetConsensus().legacyQuorumReplay.size};
    if (configured_size > 0 &&
        configured_size <= static_cast<int>(legacy::MAX_QUORUM_MEMBERS)) {
        const auto size{static_cast<std::size_t>(configured_size)};
        signers.assign(size, false);
        validMembers.assign(size, false);
    }
}

bool CFinalCommitment::IsNull() const noexcept
{
    return CountSigners() == 0 && CountValidMembers() == 0 &&
           quorumPublicKey.IsNull() && quorumVvecHash.IsNull() &&
           quorumSig.IsNull() && membersSig.IsNull();
}

bool CFinalCommitment::VerifyNull() const noexcept
{
    return VerifySizes() && IsNull();
}

bool CFinalCommitment::VerifySizes() const noexcept
{
    const int configured_size{
        Params().GetConsensus().legacyQuorumReplay.size};
    if (configured_size <= 0 ||
        configured_size > static_cast<int>(legacy::MAX_QUORUM_MEMBERS)) {
        return false;
    }
    const auto expected{static_cast<std::size_t>(configured_size)};
    return signers.size() == expected && validMembers.size() == expected;
}

bool CFinalCommitment::IsStructurallyValid(
    std::size_t expected_size,
    std::size_t actual_member_count,
    std::size_t minimum_signers,
    uint16_t expected_version) const
{
    legacy::FinalCommitment opaque;
    opaque.version = nVersion;
    opaque.quorum_hash = quorumHash;
    opaque.signers = signers;
    opaque.valid_members = validMembers;
    opaque.quorum_public_key = quorumPublicKey;
    opaque.quorum_vvec_hash = quorumVvecHash;
    opaque.quorum_signature = quorumSig;
    opaque.members_signature = membersSig;
    return opaque.IsStructurallyValid(expected_size, actual_member_count,
                                      minimum_signers, expected_version);
}

bool CFinalCommitment::Verify(const CBlockIndex* quorum_base,
                              bool) const
{
    if (quorum_base == nullptr || quorumHash != quorum_base->GetBlockHash()) {
        return false;
    }
    const auto& params{Params().GetConsensus().legacyQuorumReplay};
    const auto members{CLLMQUtils::GetAllQuorumMembers(quorum_base)};
    return IsStructurallyValid(
        static_cast<std::size_t>(params.size), members.size(),
        static_cast<std::size_t>(params.minimum_size),
        GetVersion(CLLMQUtils::IsV19Active(quorum_base->nHeight)));
}

void CFinalCommitment::ToJson(UniValue& object) const
{
    object.setObject();
    object.pushKV("version", nVersion);
    object.pushKV("quorumHash", quorumHash.ToString());
    object.pushKV("signersCount", CountSigners());
    object.pushKV("signers", CLLMQUtils::ToHexStr(signers));
    object.pushKV("validMembersCount", CountValidMembers());
    object.pushKV("validMembers", CLLMQUtils::ToHexStr(validMembers));
    object.pushKV("quorumPublicKey", quorumPublicKey.ToString());
    object.pushKV("quorumVvecHash", quorumVvecHash.ToString());
    object.pushKV("quorumSig", quorumSig.ToString());
    object.pushKV("membersSig", membersSig.ToString());
}

void CFinalCommitmentTxPayload::ToJson(UniValue& object) const
{
    object.setObject();
    UniValue commitment_object;
    commitment.ToJson(commitment_object);
    object.pushKV("version", nVersion);
    object.pushKV("height", nHeight);
    object.pushKV("commitment", commitment_object);
}

uint256 BuildCommitmentHash(
    const uint256& block_hash,
    const std::vector<bool>& valid_members,
    const CLegacyBLSPublicKey& public_key,
    const uint256& vvec_hash)
{
    return legacy::BuildCommitmentHash(
        block_hash, valid_members, public_key, vvec_hash);
}

} // namespace llmq
