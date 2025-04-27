// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_commitment.h>
#include <llmq/quorums_utils.h>

#include <evo/deterministicmns.h>
#include <evo/specialtx.h>

#include <chainparams.h>
#include <validation.h>

#include <logging.h>
#include <node/blockstorage.h>
namespace llmq
{

CFinalCommitment::CFinalCommitment(const uint256& _quorumHash) :
        quorumHash(_quorumHash),
        signers(Params().GetConsensus().llmqTypeChainLocks.size),
        validMembers(Params().GetConsensus().llmqTypeChainLocks.size)
{
}

bool CFinalCommitment::Verify(const CBlockIndex* pQuorumBaseBlockIndex, bool checkSigs) const
{
    uint16_t expected_nversion{CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION};
    expected_nversion = CLLMQUtils::IsV19Active(pQuorumBaseBlockIndex->nHeight) ? CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION : CFinalCommitment::LEGACY_BLS_NON_INDEXED_QUORUM_VERSION;
    
    if (nVersion == 0 || nVersion != expected_nversion) {
        LogPrint(BCLog::LLMQ, "q[%s] invalid nVersion=%d expectednVersion\n", quorumHash.ToString(), nVersion, expected_nversion);
        return false;
    }

    if (pQuorumBaseBlockIndex->GetBlockHash() != quorumHash) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid quorumHash\n", quorumHash.ToString());
        return false;
    }

    const auto& llmq_params = Params().GetConsensus().llmqTypeChainLocks;

    if (!VerifySizes()) {
        return false;
    }

    if (CountValidMembers() < llmq_params.minSize) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid validMembers count. validMembersCount=%d\n", quorumHash.ToString(), CountValidMembers());
        return false;
    }
    if (CountSigners() < llmq_params.minSize) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid signers count. signersCount=%d\n", quorumHash.ToString(), CountSigners());
        return false;
    }
    if (!quorumPublicKey.IsValid()) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid quorumPublicKey\n", quorumHash.ToString());
        return false;
    }
    if (quorumVvecHash.IsNull()) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid quorumVvecHash\n", quorumHash.ToString());
        return false;
    }
    if (!membersSig.IsValid()) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid membersSig\n", quorumHash.ToString());
        return false;
    }
    if (!quorumSig.IsValid()) {
        LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid vvecSig\n", quorumHash.ToString());
        return false;
    }
    auto members = CLLMQUtils::GetAllQuorumMembers(pQuorumBaseBlockIndex);
    if (LogAcceptCategory(BCLog::LLMQ, BCLog::Level::Debug)) {
        std::stringstream ss;
        std::stringstream ss2;
        for (size_t i = 0; i < (size_t)llmq_params.size; i++) {
            ss << "v[" << i << "]=" << validMembers[i];
            ss2 << "s[" << i << "]=" << signers[i];
        }
        LogPrint(BCLog::LLMQ, "CFinalCommitment::%s mns[%d] validMembers[%s] signers[%s]\n", __func__, members.size(), ss.str(), ss2.str());
    }

    for (size_t i = members.size(); i < (size_t)llmq_params.size; i++) {
        if (validMembers[i]) {
            LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid validMembers bitset. bit %d should not be set\n", quorumHash.ToString(), i);
            return false;
        }
        if (signers[i]) {
            LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid signers bitset. bit %d should not be set\n", quorumHash.ToString(), i);
            return false;
        }
    }

    // sigs are only checked when the block is processed
    if (checkSigs) {
        uint256 commitmentHash = BuildCommitmentHash(quorumHash, validMembers, quorumPublicKey, quorumVvecHash);
        if (LogAcceptCategory(BCLog::LLMQ, BCLog::Level::Debug)) {
            std::stringstream ss3;
            for (const auto &mn: members) {
                ss3 << mn->proTxHash.ToString().substr(0, 4) << " | ";
            }
            LogPrint(BCLog::LLMQ, "CFinalCommitment::%s members[%s] quorumPublicKey[%s] commitmentHash[%s]\n",
                                     __func__, ss3.str(), quorumPublicKey.ToString(), commitmentHash.ToString());
        }
        std::vector<CBLSPublicKey> memberPubKeys;
        for (size_t i = 0; i < members.size(); i++) {
            if (!signers[i]) {
                continue;
            }
            memberPubKeys.emplace_back(members[i]->pdmnState->pubKeyOperator.Get());
        }

        if (!membersSig.VerifySecureAggregated(memberPubKeys, commitmentHash)) {
            LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid aggregated members signature\n", quorumHash.ToString());
            return false;
        }

        if (!quorumSig.VerifyInsecure(quorumPublicKey, commitmentHash)) {
            LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] invalid quorum signature\n", quorumHash.ToString());
            return false;
        }
    }

    LogPrint(BCLog::LLMQ, "CFinalCommitment -- q[%s] VALID QUORUM\n", quorumHash.ToString());

    return true;
}

bool CFinalCommitment::VerifyNull() const
{
    if (!IsNull() || !VerifySizes()) {
        return false;
    }

    return true;
}

bool CFinalCommitment::VerifySizes() const
{
    const Consensus::LLMQParams& params = Params().GetConsensus().llmqTypeChainLocks;
    if (signers.size() != (size_t)params.size) {
        LogPrint(BCLog::LLMQ, "invalid signers.size=%d\n", signers.size());
        return false;
    }
    if (validMembers.size() != (size_t)params.size) {
        LogPrint(BCLog::LLMQ, "invalid signers.size=%d\n", signers.size());
        return false;
    }
    return true;
}

uint256 BuildCommitmentHash(const uint256& blockHash, const std::vector<bool>& validMembers, const CBLSPublicKey& pubKey, const uint256& vvecHash)
{
    CHashWriter hw(SER_GETHASH, 0);
    hw << blockHash;
    hw << DYNBITSET(validMembers);
    hw << pubKey;
    hw << vvecHash;
    return hw.GetHash();
}

} // namespace llmq
