// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governancevote.h>

#include <bls/bls.h>
#include <chainparams.h>
#include <key.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <messagesigner.h>
#include <net_processing.h>
#include <util/string.h>
#include <validation.h>
#include <timedata.h>
#include <evo/deterministicmns.h>

std::string CGovernanceVoting::ConvertOutcomeToString(vote_outcome_enum_t nOutcome)
{
    static const std::map<vote_outcome_enum_t, std::string> mapOutcomeString = {
        { VOTE_OUTCOME_NONE, "none" },
        { VOTE_OUTCOME_YES, "yes" },
        { VOTE_OUTCOME_NO, "no" },
        { VOTE_OUTCOME_ABSTAIN, "abstain" } };

    const auto& it = mapOutcomeString.find(nOutcome);
    if (it == mapOutcomeString.end()) {
        LogPrintf("CGovernanceVoting::%s -- ERROR: Unknown outcome %d\n", __func__, nOutcome);
        return "error";
    }
    return it->second;
}

std::string CGovernanceVoting::ConvertSignalToString(vote_signal_enum_t nSignal)
{
    static const std::map<vote_signal_enum_t, std::string> mapSignalsString = {
        { VOTE_SIGNAL_FUNDING, "funding" },
        { VOTE_SIGNAL_VALID, "valid" },
        { VOTE_SIGNAL_DELETE, "delete" },
        { VOTE_SIGNAL_ENDORSED, "endorsed" } };

    const auto& it = mapSignalsString.find(nSignal);
    if (it == mapSignalsString.end()) {
        LogPrintf("CGovernanceVoting::%s -- ERROR: Unknown signal %d\n", __func__, nSignal);
        return "none";
    }
    return it->second;
}


vote_outcome_enum_t CGovernanceVoting::ConvertVoteOutcome(const std::string& strVoteOutcome)
{
    static const std::map<std::string, vote_outcome_enum_t> mapStringOutcome = {
        { "none", VOTE_OUTCOME_NONE },
        { "yes", VOTE_OUTCOME_YES },
        { "no", VOTE_OUTCOME_NO },
        { "abstain", VOTE_OUTCOME_ABSTAIN } };

    const auto& it = mapStringOutcome.find(strVoteOutcome);
    if (it == mapStringOutcome.end()) {
        LogPrintf("CGovernanceVoting::%s -- ERROR: Unknown outcome %s\n", __func__, strVoteOutcome);
        return VOTE_OUTCOME_NONE;
    }
    return it->second;

}

vote_signal_enum_t CGovernanceVoting::ConvertVoteSignal(const std::string& strVoteSignal)
{
    static const std::map<std::string, vote_signal_enum_t> mapStrVoteSignals = {
        {"funding", VOTE_SIGNAL_FUNDING},
        {"valid", VOTE_SIGNAL_VALID},
        {"delete", VOTE_SIGNAL_DELETE},
        {"endorsed", VOTE_SIGNAL_ENDORSED}};

    const auto& it = mapStrVoteSignals.find(strVoteSignal);
    if (it == mapStrVoteSignals.end()) {
        LogPrintf("CGovernanceVoting::%s -- ERROR: Unknown signal %s\n", __func__, strVoteSignal);
        return VOTE_SIGNAL_NONE;
    }
    return it->second;
}

CGovernanceVote::CGovernanceVote() :
    fValid(true),
    fSynced(false),
    nVoteSignal(int(VOTE_SIGNAL_NONE)),
    masternodeOutpoint(),
    nParentHash(),
    nVoteOutcome(int(VOTE_OUTCOME_NONE)),
    nTime(0),
    vchSig()
{
}

CGovernanceVote::CGovernanceVote(const COutPoint& outpointMasternodeIn, const uint256& nParentHashIn, vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn) :
    fValid(true),
    fSynced(false),
    nVoteSignal(eVoteSignalIn),
    masternodeOutpoint(outpointMasternodeIn),
    nParentHash(nParentHashIn),
    nVoteOutcome(eVoteOutcomeIn),
    nTime(TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime())),
    vchSig()
{
    UpdateHash();
}

std::string CGovernanceVote::ToString() const
{
    std::ostringstream ostr;
    ostr << masternodeOutpoint.ToStringShort() << ":"
         << nTime << ":"
         << CGovernanceVoting::ConvertOutcomeToString(GetOutcome()) << ":"
         << CGovernanceVoting::ConvertSignalToString(GetSignal());
    return ostr.str();
}

void CGovernanceVote::Relay(PeerManager& peerman, const CDeterministicMNList& tip_mn_list) const
{
    // Do not relay until fully synced
    if (!masternodeSync.IsSynced()) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::Relay -- won't relay until fully synced\n");
        return;
    }

    auto dmn = tip_mn_list.GetMNByCollateral(masternodeOutpoint);
    if (!dmn) {
        return;
    }

    CInv inv(MSG_GOVERNANCE_OBJECT_VOTE, GetHash());
    peerman.RelayInv(inv);
}

void CGovernanceVote::UpdateHash() const
{
    // Note: doesn't match serialization

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << masternodeOutpoint;
    ss << nParentHash;
    ss << nVoteSignal;
    ss << nVoteOutcome;
    ss << nTime;
    *const_cast<uint256*>(&hash) = ss.GetHash();
}

uint256 CGovernanceVote::GetHash() const
{
    return hash;
}

uint256 CGovernanceVote::GetSignatureHash() const
{
    return SerializeHash(*this);
}

bool CGovernanceVote::Sign(const CKey& key, const CKeyID& keyID)
{
    const uint256 signatureHash = GetSignatureHash();

    if (!CHashSigner::SignHash(signatureHash, key, vchSig)) {
        LogPrintf("CGovernanceVote::Sign -- SignHash() failed\n");
        return false;
    }

    if (!CHashSigner::VerifyHash(signatureHash, keyID, vchSig)) {
        LogPrintf("CGovernanceVote::Sign -- VerifyHash() failed\n");
        return false;
    }


    return true;
}

bool CGovernanceVote::CheckSignature(const CKeyID& keyID) const
{
    if (!CHashSigner::VerifyHash(GetSignatureHash(), keyID, vchSig)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- VerifyHash() failed\n");
        return false;
    }
 

    return true;
}

bool CGovernanceVote::Sign()
{
    CBLSSignature sig = activeMasternodeInfo.blsKeyOperator->Sign(GetSignatureHash(), false);
    if (!sig.IsValid()) {
        return false;
    }
    vchSig = sig.ToByteVector(false);
    return true;
}

bool CGovernanceVote::CheckSignature(const CBLSPublicKey& pubKey) const
{
    CBLSSignature sig;
    sig.SetBytes(vchSig, false);
    if (!sig.VerifyInsecure(pubKey, GetSignatureHash(), false)) {
        LogPrintf("CGovernanceVote::CheckSignature -- VerifyInsecure() failed\n");
        return false;
    }
    return true;
}

bool CGovernanceVote::IsValid(const CDeterministicMNList& tip_mn_list, bool useVotingKey) const
{
    if (nTime > TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) + (60 * 60)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- vote is too far ahead of current time - %s - nTime %lli - Max Time %lli\n", GetHash().ToString(), nTime, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) + (60 * 60));
        return false;
    }

    // support up to MAX_SUPPORTED_VOTE_SIGNAL, can be extended
    if (nVoteSignal > MAX_SUPPORTED_VOTE_SIGNAL) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Client attempted to vote on invalid signal(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    // 0=none, 1=yes, 2=no, 3=abstain. Beyond that reject votes
    if (nVoteOutcome > 3) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Client attempted to vote on invalid outcome(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    auto dmn = tip_mn_list.GetMNByCollateral(masternodeOutpoint);
    if (!dmn) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Unknown Masternode - %s\n", masternodeOutpoint.ToStringShort());
        return false;
    }

    if (useVotingKey) {
        return CheckSignature(dmn->pdmnState->keyIDVoting);
    } else {
        return CheckSignature(dmn->pdmnState->pubKeyOperator.Get());
    }
}

bool operator==(const CGovernanceVote& vote1, const CGovernanceVote& vote2)
{
    bool fResult = ((vote1.masternodeOutpoint == vote2.masternodeOutpoint) &&
                    (vote1.nParentHash == vote2.nParentHash) &&
                    (vote1.nVoteOutcome == vote2.nVoteOutcome) &&
                    (vote1.nVoteSignal == vote2.nVoteSignal) &&
                    (vote1.nTime == vote2.nTime));
    return fResult;
}

bool operator<(const CGovernanceVote& vote1, const CGovernanceVote& vote2)
{
    bool fResult = (vote1.masternodeOutpoint < vote2.masternodeOutpoint);
    if (!fResult) {
        return false;
    }
    fResult = (vote1.masternodeOutpoint == vote2.masternodeOutpoint);

    fResult = fResult && (vote1.nParentHash < vote2.nParentHash);
    if (!fResult) {
        return false;
    }
    fResult = (vote1.nParentHash == vote2.nParentHash);

    fResult = fResult && (vote1.nVoteOutcome < vote2.nVoteOutcome);
    if (!fResult) {
        return false;
    }
    fResult = (vote1.nVoteOutcome == vote2.nVoteOutcome);

    fResult = fResult && (vote1.nVoteSignal == vote2.nVoteSignal);
    if (!fResult) {
        return false;
    }
    fResult = (vote1.nVoteSignal == vote2.nVoteSignal);

    fResult = fResult && (vote1.nTime < vote2.nTime);

    return fResult;
}
