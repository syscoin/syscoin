// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governancevote.h>

#include <chain.h>
#include <chainparams.h>
#include <governance/pq_governance_auth_interface.h> // SYSCOIN: declaration-only auth boundary.
#include <key.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodesync.h>
#include <messagesigner.h>
#include <net_processing.h>
#include <util/string.h>
#include <validation.h>
#include <timedata.h>
#include <evo/deterministicmns.h>

#include <tuple>

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

std::optional<llmq::pq::GovernanceAuthPurpose>
GetGovernanceVoteAuthPurpose(
    int governance_object_type, vote_signal_enum_t signal) noexcept
{
    if (signal <= VOTE_SIGNAL_NONE || signal > MAX_SUPPORTED_VOTE_SIGNAL) {
        return std::nullopt;
    }
    if (governance_object_type == GOVERNANCE_OBJECT_TRIGGER) {
        return llmq::pq::GovernanceAuthPurpose::TRIGGER_VOTE;
    }
    if (governance_object_type == GOVERNANCE_OBJECT_PROPOSAL &&
        signal != VOTE_SIGNAL_FUNDING) {
        return llmq::pq::GovernanceAuthPurpose::PROPOSAL_VOTE;
    }
    return std::nullopt;
}

bool IsPotentialOrphanGovernanceVoteAuthorization(
    vote_signal_enum_t signal, std::size_t signature_size) noexcept
{
    if (signal <= VOTE_SIGNAL_NONE || signal > MAX_SUPPORTED_VOTE_SIGNAL) {
        return false;
    }
    if (signature_size ==
        llmq::pq::GovernanceAuthorization::WIRE_SIZE) {
        return true;
    }
    // Without the parent, compact ECDSA can only become a proposal funding
    // vote; every other supported object/signal pairing requires SLH.
    return signal == VOTE_SIGNAL_FUNDING &&
           signature_size == CPubKey::COMPACT_SIGNATURE_SIZE;
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

bool CGovernanceVote::HasSameWireEncoding(
    const CGovernanceVote& other) const
{
    return *this == other && vchSig == other.vchSig;
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

bool CGovernanceVote::SignPQ(const CBlockIndex& signing_block,
                             const uint256& pro_tx_hash,
                             uint32_t global_key_version,
                             llmq::pq::GovernanceAuthPurpose purpose)
{
    // SYSCOIN: SLH signing must never inherit consensus/governance locks.
    AssertLockNotHeld(cs_main);
    AssertGovernanceLockNotHeld();

    llmq::pq::GlobalKeyRecord current_key;
    std::string error;
    if (!llmq::pq::GetCurrentGovernanceSigningKey(
            signing_block, pro_tx_hash, global_key_version, current_key,
            error)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::SignPQ -- %s\n", error);
        return false;
    }

    llmq::pq::GovernanceAuthorization authorization;
    authorization.signed_height = signing_block.nHeight;
    authorization.signed_block_hash = signing_block.GetBlockHash();
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = global_key_version;
    const auto digest{llmq::pq::GetGovernanceAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, current_key,
        authorization, purpose, GetSignatureHash())};
    const bool signed_authorization{digest &&
        (purpose == llmq::pq::GovernanceAuthPurpose::TRIGGER_VOTE
             ? SignActiveMasternodeGovernanceVote(
                   pro_tx_hash, global_key_version, *digest,
                   authorization.signature)
             : purpose == llmq::pq::GovernanceAuthPurpose::PROPOSAL_VOTE &&
                   SignActiveMasternodeGovernanceProposalVote(
                       pro_tx_hash, global_key_version, *digest,
                       authorization.signature))};
    if (!signed_authorization ||
        !llmq::pq::EncodeGovernanceAuthorization(authorization, vchSig)) {
        vchSig.clear();
        return false;
    }
    return true;
}

bool CGovernanceVote::CheckPQSignature(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    llmq::pq::GovernanceAuthPurpose purpose,
    std::string& error) const
{
    // SYSCOIN: SLH verification must never inherit consensus/governance locks.
    AssertLockNotHeld(cs_main);
    AssertGovernanceLockNotHeld();

    return llmq::pq::VerifyGovernanceAuthorizationForBranch(
        validation_branch, validation_mn_list, masternodeOutpoint,
        purpose, GetSignatureHash(), vchSig, error);
}

bool CGovernanceVote::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContextForBranch(
        validation_branch, validation_mn_list, masternodeOutpoint, vchSig,
        authorization, error);
}

bool CGovernanceVote::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& current_snapshot,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContext(
        validation_branch, validation_mn_list, current_snapshot,
        masternodeOutpoint, vchSig, authorization, error);
}

bool CGovernanceVote::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistryReadView& current_snapshot,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContext(
        validation_branch, validation_mn_list, current_snapshot,
        masternodeOutpoint, vchSig, authorization, error);
}

bool CGovernanceVote::IsValidBasic(
    const CDeterministicMNList& validation_mn_list) const
{
    if (nTime > TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) + (60 * 60)) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- vote is too far ahead of current time - %s - nTime %lli - Max Time %lli\n", GetHash().ToString(), nTime, TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime()) + (60 * 60));
        return false;
    }

    // support up to MAX_SUPPORTED_VOTE_SIGNAL, can be extended
    if (nVoteSignal <= VOTE_SIGNAL_NONE ||
        nVoteSignal > MAX_SUPPORTED_VOTE_SIGNAL) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Client attempted to vote on invalid signal(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    // 0=none, 1=yes, 2=no, 3=abstain. Beyond that reject votes
    if (nVoteOutcome <= VOTE_OUTCOME_NONE || nVoteOutcome > VOTE_OUTCOME_ABSTAIN) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Client attempted to vote on invalid outcome(%d) - %s\n", nVoteSignal, GetHash().ToString());
        return false;
    }

    auto dmn =
        validation_mn_list.GetValidMNByCollateral(masternodeOutpoint);
    if (!dmn) {
        LogPrint(BCLog::GOBJECT, "CGovernanceVote::IsValid -- Unknown or inactive Masternode - %s\n", masternodeOutpoint.ToStringShort());
        return false;
    }

    return true;
}

bool CGovernanceVote::IsValid(
    const CDeterministicMNList& validation_mn_list) const
{
    if (!IsValidBasic(validation_mn_list)) return false;
    const auto dmn{
        validation_mn_list.GetValidMNByCollateral(masternodeOutpoint)};
    return dmn && CheckSignature(dmn->pdmnState->keyIDVoting);
}

bool CGovernanceVote::IsValidPQ(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    llmq::pq::GovernanceAuthPurpose purpose,
    std::string& error) const
{
    if (!IsValidBasic(validation_mn_list)) {
        error = "invalid governance vote fields or masternode identity";
        return false;
    }
    return CheckPQSignature(validation_branch, validation_mn_list, purpose,
                            error);
}

bool CGovernanceVote::IsValidPQContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    if (!IsValidBasic(validation_mn_list)) {
        error = "invalid governance vote fields or masternode identity";
        return false;
    }
    return CheckPQAuthorizationContext(validation_branch, validation_mn_list,
                                       error);
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
    // SYSCOIN: CacheMultiMap requires a strict order consistent with vote
    // equality. The signature is intentionally excluded from both because it
    // does not change the logical vote identity.
    return std::tie(vote1.masternodeOutpoint, vote1.nParentHash,
                    vote1.nVoteOutcome, vote1.nVoteSignal, vote1.nTime) <
           std::tie(vote2.masternodeOutpoint, vote2.nParentHash,
                    vote2.nVoteOutcome, vote2.nVoteSignal, vote2.nTime);
}
