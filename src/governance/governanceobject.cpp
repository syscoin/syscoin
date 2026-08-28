// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/governanceobject.h>

#include <chain.h>
#include <chainparams.h>
#include <core_io.h>
#include <evo/deterministicmns.h>
#include <governance/governance.h>
#include <governance/pq_governance_auth_interface.h> // SYSCOIN: declaration-only auth boundary.
#include <governance/governancevalidators.h>
#include <masternode/activemasternode.h>
#include <masternode/masternodemeta.h>
#include <masternode/masternodesync.h>
#include <net_processing.h>
#include <timedata.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <node/transaction.h>

#include <string>

CGovernanceObject::CGovernanceObject() :
    cs(),
    m_obj{},
    nDeletionTime(0),
    fCachedLocalValidity(false),
    strLocalValidityError(),
    fCachedFunding(false),
    fCachedValid(true),
    fCachedDelete(false),
    fCachedDeleteByVotes(false),
    fCachedEndorsed(false),
    fDirtyCache(true),
    fExpired(false),
    fUnparsable(false),
    mapCurrentMNVotes(),
    fileVotes()
{
    // PARSE JSON DATA STORAGE (VCHDATA)
    LoadData();
}

CGovernanceObject::CGovernanceObject(const uint256& nHashParentIn, int nRevisionIn, int64_t nTimeIn, const uint256& nCollateralHashIn, const std::string& strDataHexIn) :
    cs(),
    m_obj{nHashParentIn, nRevisionIn, nTimeIn, nCollateralHashIn, strDataHexIn},
    nDeletionTime(0),
    fCachedLocalValidity(false),
    strLocalValidityError(),
    fCachedFunding(false),
    fCachedValid(true),
    fCachedDelete(false),
    fCachedDeleteByVotes(false),
    fCachedEndorsed(false),
    fDirtyCache(true),
    fExpired(false),
    fUnparsable(false),
    mapCurrentMNVotes(),
    fileVotes()
{
    // PARSE JSON DATA STORAGE (VCHDATA)
    LoadData();
}

CGovernanceObject::CGovernanceObject(const CGovernanceObject& other) :
    cs(),
    m_obj{other.m_obj},
    nDeletionTime(other.nDeletionTime),
    fCachedLocalValidity(other.fCachedLocalValidity),
    strLocalValidityError(other.strLocalValidityError),
    fCachedFunding(other.fCachedFunding),
    fCachedValid(other.fCachedValid),
    fCachedDelete(other.fCachedDelete),
    fCachedDeleteByVotes(other.fCachedDeleteByVotes),
    fCachedEndorsed(other.fCachedEndorsed),
    fDirtyCache(other.fDirtyCache),
    fExpired(other.fExpired),
    fUnparsable(other.fUnparsable),
    mapCurrentMNVotes(other.mapCurrentMNVotes),
    fileVotes(other.fileVotes)
{
}

std::shared_ptr<const GovernancePageImmutableSnapshot>
CGovernanceObject::GetVotePageSnapshot(
    const std::shared_ptr<GovernancePageSnapshotBudget>& budget,
    uint64_t instance_id,
    uint64_t validation_context_epoch,
    std::optional<std::size_t> retained_bytes) const
{
    LOCK(cs);
    return fileVotes.GetPageSnapshot(
        GetHash(), budget, instance_id,
        validation_context_epoch, retained_bytes);
}

std::optional<std::size_t>
CGovernanceObject::GetVotePageSnapshotRetainedBytes() const
{
    LOCK(cs);
    return fileVotes.GetPageSnapshotRetainedBytes();
}

std::shared_ptr<const GovernancePageImmutableSnapshot>
CGovernanceObject::GetCachedVotePageSnapshot(
    uint64_t validation_context_epoch) const
{
    LOCK(cs);
    return fileVotes.GetCachedPageSnapshot(
        validation_context_epoch);
}

bool CGovernanceObject::SerializeVoteForPage(
    const uint256& vote_hash, CDataStream& stream) const
{
    LOCK(cs);
    return fileVotes.SerializeVoteToStream(vote_hash, stream);
}

bool CGovernanceObject::HasVoteForPage(const uint256& vote_hash) const
{
    LOCK(cs);
    return fileVotes.HasVote(vote_hash);
}

bool CGovernanceObject::ProcessVote(const CBlockIndex& validation_branch,
                                    const CDeterministicMNList& tip_mn_list,
                                    const CGovernanceVote& vote,
                                    CGovernanceException& exception,
                                    bool pq_signature_preverified)
{
    LOCK(cs);

    // do not process already known valid votes twice
    if (fileVotes.HasVote(vote.GetHash())) {
        // nothing to do here, not an error
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Already known valid vote";
        LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_NONE);
        return false;
    }

    // SLH verification happens without chain, governance, or object locks.
    // This method may only repeat the cheap branch/authority binding before
    // mutating an operator-authorized vote.
    const auto pq_purpose{GetGovernanceVoteAuthPurpose(
        GetObjectType(), vote.GetSignal())};
    if (pq_purpose && !pq_signature_preverified) {
        const std::string error{
            "CGovernanceObject::ProcessVote -- operator vote requires preverified SLH authorization"};
        exception = CGovernanceException(
            error, GOVERNANCE_EXCEPTION_PERMANENT_ERROR);
        LogPrint(BCLog::GOBJECT, "%s\n", error);
        return false;
    }

    auto dmn = tip_mn_list.GetValidMNByCollateral(
        vote.GetMasternodeOutpoint());
    if (!dmn) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Masternode " << vote.GetMasternodeOutpoint().ToStringShort() << " not found or inactive";
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }

    vote_signal_enum_t eSignal = vote.GetSignal();
    if (eSignal == VOTE_SIGNAL_NONE) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Vote signal: none";
        LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
        exception = CGovernanceException(
            ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }
    if (eSignal > MAX_SUPPORTED_VOTE_SIGNAL) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Unsupported vote signal: " << CGovernanceVoting::ConvertSignalToString(vote.GetSignal());
        LogPrintf("%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }

    // Validate authorization before any temporal/supersession shortcut. A
    // logical vote hash omits signature bytes, so an invalid alternate wire
    // form must never be classified as an already-valid obsolete vote.
    std::string signature_error;
    const bool signature_valid = pq_purpose
        ? vote.IsValidPQContext(validation_branch, tip_mn_list,
                               signature_error)
        : vote.IsValid(tip_mn_list);
    if (!signature_valid) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Invalid vote"
             << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToStringShort()
             << ", governance object hash = " << GetHash().ToString()
             << ", vote hash = " << vote.GetHash().ToString();
        if (!signature_error.empty()) {
            ostr << ", reason = " << signature_error;
        }
        LogPrintf("%s\n", ostr.str());
        exception = CGovernanceException(
            ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR, 20);
        return false;
    }

    auto it = mapCurrentMNVotes.emplace(vote_m_t::value_type(vote.GetMasternodeOutpoint(), vote_rec_t())).first;
    vote_rec_t& voteRecordRef = it->second;
    auto it2 = voteRecordRef.mapInstances.emplace(vote_instance_m_t::value_type(int(eSignal), vote_instance_t())).first;
    vote_instance_t& voteInstanceRef = it2->second;

    // Reject obsolete votes
    if (vote.GetTimestamp() < voteInstanceRef.nCreationTime) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Obsolete vote";
        LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_NONE);
        return false;
    } else if (vote.GetTimestamp() == voteInstanceRef.nCreationTime) {
        // Someone is doing something fishy, there can be no two votes from the same masternode
        // with the same timestamp for the same object and signal and yet different hash/outcome.
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Invalid vote, same timestamp for the different outcome";
        if (vote.GetOutcome() < voteInstanceRef.eOutcome) {
            // This is an arbitrary comparison, we have to agree on some way
            // to pick the "winning" vote.
            ostr << ", rejected";
            LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
            exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_NONE);
            return false;
        }
        ostr << ", accepted";
        LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
    }

    int64_t nNow = TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
    int64_t nVoteTimeUpdate = voteInstanceRef.nTime;
    if (governance->AreRateChecksEnabled()) {
        int64_t nTimeDelta = nNow - voteInstanceRef.nTime;
        if (nTimeDelta < GOVERNANCE_UPDATE_MIN) {
            std::ostringstream ostr;
            ostr << "CGovernanceObject::ProcessVote -- Masternode voting too often"
                 << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToStringShort()
                 << ", governance object hash = " << GetHash().ToString()
                 << ", time delta = " << nTimeDelta;
            LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
            exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_TEMPORARY_ERROR);
            return false;
        }
        nVoteTimeUpdate = nNow;
    }

    if (!mmetaman->AddGovernanceVote(dmn->proTxHash, vote.GetParentHash())) {
        std::ostringstream ostr;
        ostr << "CGovernanceObject::ProcessVote -- Unable to add governance vote"
             << ", MN outpoint = " << vote.GetMasternodeOutpoint().ToStringShort()
             << ", governance object hash = " << GetHash().ToString();
        LogPrint(BCLog::GOBJECT, "%s\n", ostr.str());
        exception = CGovernanceException(ostr.str(), GOVERNANCE_EXCEPTION_PERMANENT_ERROR);
        return false;
    }

    voteInstanceRef = vote_instance_t(vote.GetOutcome(), nVoteTimeUpdate, vote.GetTimestamp());
    fileVotes.AddVote(vote);
    fDirtyCache = true;
    // SEND NOTIFICATION TO SCRIPT/ZMQ
    GetMainSignals().NotifyGovernanceVote(vote.GetHash());
    return true;
}

void CGovernanceObject::ClearMasternodeVotes(const CDeterministicMNList& tip_mn_list)
{
    LOCK(cs);

    auto it = mapCurrentMNVotes.begin();
    while (it != mapCurrentMNVotes.end()) {
        if (!tip_mn_list.HasMNByCollateral(it->first)) {
            fileVotes.RemoveVotesFromMasternode(it->first);
            mapCurrentMNVotes.erase(it++);
            fDirtyCache = true;
        } else {
            ++it;
        }
    }
}

std::set<uint256>
CGovernanceObject::RemoveInvalidDelegatedFundingVotes(
    const CDeterministicMNList& validation_mn_list,
    const std::optional<COutPoint>& masternode_filter,
    std::size_t* checked_votes,
    std::set<COutPoint>* removed_operators)
{
    LOCK(cs);
    if (GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) return {};

    std::set<uint256> removed_votes;
    const auto inspect_vote = [&](const CGovernanceVote& vote) {
        if (vote.GetSignal() != VOTE_SIGNAL_FUNDING) return true;
        if (checked_votes != nullptr) ++*checked_votes;
        if (!vote.IsValid(validation_mn_list)) {
            removed_votes.emplace(vote.GetHash());
            if (removed_operators != nullptr) {
                removed_operators->insert(
                    vote.GetMasternodeOutpoint());
            }
        }
        return true;
    };
    if (masternode_filter) {
        fileVotes.ForEachVoteFromMasternode(*masternode_filter,
                                            inspect_vote);
    } else {
        fileVotes.ForEachVote(inspect_vote);
    }
    if (removed_votes.empty()) return removed_votes;

    fileVotes.RemoveVotes(removed_votes);
    const uint256 parent_hash{GetHash()};
    auto vote_it = masternode_filter
        ? mapCurrentMNVotes.lower_bound(*masternode_filter)
        : mapCurrentMNVotes.begin();
    while (vote_it != mapCurrentMNVotes.end() &&
           (!masternode_filter ||
            vote_it->first == *masternode_filter)) {
        auto& instances{vote_it->second.mapInstances};
        for (auto instance_it = instances.begin();
             instance_it != instances.end();) {
            CGovernanceVote reconstructed{
                vote_it->first, parent_hash,
                static_cast<vote_signal_enum_t>(instance_it->first),
                instance_it->second.eOutcome};
            reconstructed.SetTime(instance_it->second.nCreationTime);
            if (removed_votes.contains(reconstructed.GetHash())) {
                instance_it = instances.erase(instance_it);
            } else {
                ++instance_it;
            }
        }
        if (instances.empty()) {
            vote_it = mapCurrentMNVotes.erase(vote_it);
        } else {
            ++vote_it;
        }
    }
    fDirtyCache = true;
    return removed_votes;
}

template <typename RegistrySnapshot>
std::set<uint256> CGovernanceObject::RemoveInvalidPQVotesImpl(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const RegistrySnapshot& current_snapshot,
    const std::optional<COutPoint>& masternode_filter,
    std::size_t* checked_votes,
    std::set<COutPoint>* removed_operators)
{
    LOCK(cs);
    std::set<uint256> removed_votes;
    const auto inspect_vote = [&](const CGovernanceVote& vote) {
        if (!GetGovernanceVoteAuthPurpose(
                GetObjectType(), vote.GetSignal())) {
            return true;
        }
        if (checked_votes != nullptr) ++*checked_votes;
        std::string error;
        if (!vote.CheckPQAuthorizationContext(
                validation_branch, validation_mn_list, current_snapshot,
                error)) {
            removed_votes.emplace(vote.GetHash());
            if (removed_operators != nullptr) {
                removed_operators->insert(
                    vote.GetMasternodeOutpoint());
            }
        }
        return true;
    };
    if (masternode_filter) {
        fileVotes.ForEachVoteFromMasternode(*masternode_filter,
                                            inspect_vote);
    } else {
        fileVotes.ForEachVote(inspect_vote);
    }
    if (removed_votes.empty()) return removed_votes;

    fileVotes.RemoveVotes(removed_votes);
    const uint256 parent_hash{GetHash()};
    auto vote_it = masternode_filter
        ? mapCurrentMNVotes.lower_bound(*masternode_filter)
        : mapCurrentMNVotes.begin();
    while (vote_it != mapCurrentMNVotes.end() &&
           (!masternode_filter || vote_it->first == *masternode_filter)) {
        auto& instances{vote_it->second.mapInstances};
        for (auto instance_it = instances.begin();
             instance_it != instances.end();) {
            CGovernanceVote reconstructed{
                vote_it->first, parent_hash,
                static_cast<vote_signal_enum_t>(instance_it->first),
                instance_it->second.eOutcome};
            reconstructed.SetTime(instance_it->second.nCreationTime);
            if (removed_votes.contains(reconstructed.GetHash())) {
                instance_it = instances.erase(instance_it);
            } else {
                ++instance_it;
            }
        }
        if (instances.empty()) {
            vote_it = mapCurrentMNVotes.erase(vote_it);
        } else {
            ++vote_it;
        }
    }
    fDirtyCache = true;
    return removed_votes;
}

std::set<uint256> CGovernanceObject::RemoveInvalidPQVotes(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& current_snapshot,
    const std::optional<COutPoint>& masternode_filter,
    std::size_t* checked_votes,
    std::set<COutPoint>* removed_operators)
{
    return RemoveInvalidPQVotesImpl(
        validation_branch, validation_mn_list, current_snapshot,
        masternode_filter, checked_votes, removed_operators);
}

std::set<uint256> CGovernanceObject::RemoveInvalidPQVotes(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistryReadView& current_snapshot,
    const std::optional<COutPoint>& masternode_filter,
    std::size_t* checked_votes,
    std::set<COutPoint>* removed_operators)
{
    return RemoveInvalidPQVotesImpl(
        validation_branch, validation_mn_list, current_snapshot,
        masternode_filter, checked_votes, removed_operators);
}

bool CGovernanceObject::HasPQVoteFromMasternode(
    const COutPoint& masternode) const
{
    LOCK(cs);
    bool found{false};
    fileVotes.ForEachVoteFromMasternode(
        masternode, [&](const CGovernanceVote& vote) {
            found = GetGovernanceVoteAuthPurpose(
                        GetObjectType(), vote.GetSignal())
                        .has_value();
            return !found;
        });
    return found;
}

bool CGovernanceObject::HasDelegatedFundingVoteFromMasternode(
    const COutPoint& masternode) const
{
    LOCK(cs);
    bool found{false};
    if (GetObjectType() != GOVERNANCE_OBJECT_PROPOSAL) return false;
    fileVotes.ForEachVoteFromMasternode(
        masternode, [&](const CGovernanceVote& vote) {
            found = vote.GetSignal() == VOTE_SIGNAL_FUNDING;
            return !found;
        });
    return found;
}

bool CGovernanceObject::HasStoredSupersedingVote(
    const CGovernanceVote& vote) const
{
    LOCK(cs);
    bool found{false};
    fileVotes.ForEachVoteFromMasternode(
        vote.GetMasternodeOutpoint(), [&](const CGovernanceVote& current) {
            if (current.GetParentHash() != vote.GetParentHash() ||
                current.GetSignal() != vote.GetSignal()) {
                return true;
            }
            found = current.GetTimestamp() > vote.GetTimestamp() ||
                (current.GetTimestamp() == vote.GetTimestamp() &&
                 current.GetOutcome() >= vote.GetOutcome());
            return !found;
        });
    return found;
}

uint256 CGovernanceObject::GetHash() const
{
    return m_obj.GetHash();
}

uint256 CGovernanceObject::GetDataHash() const
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << GetDataAsHexString();

    return ss.GetHash();
}

bool CGovernanceObject::HasSameWireEncoding(
    const CGovernanceObject& other) const
{
    return m_obj.type.GetValue() == other.m_obj.type.GetValue() &&
           m_obj.hashParent == other.m_obj.hashParent &&
           m_obj.revision == other.m_obj.revision &&
           m_obj.time == other.m_obj.time &&
           m_obj.collateralHash == other.m_obj.collateralHash &&
           m_obj.masternodeOutpoint == other.m_obj.masternodeOutpoint &&
           m_obj.vchSig == other.m_obj.vchSig &&
           m_obj.vchData == other.m_obj.vchData;
}

uint256 CGovernanceObject::GetSignatureHash() const
{
    return SerializeHash(*this);
}

void CGovernanceObject::SetMasternodeOutpoint(const COutPoint& outpoint)
{
    m_obj.masternodeOutpoint = outpoint;
}

bool CGovernanceObject::SignPQ(const CBlockIndex& signing_block,
                               const uint256& pro_tx_hash,
                               uint32_t global_key_version)
{
    // SYSCOIN: SLH signing must never inherit consensus/governance locks.
    AssertLockNotHeld(cs_main);
    if (governance) AssertLockNotHeld(governance->cs);
    AssertLockNotHeld(cs);

    llmq::pq::GlobalKeyRecord current_key;
    std::string error;
    if (!llmq::pq::GetCurrentGovernanceSigningKey(
            signing_block, pro_tx_hash, global_key_version, current_key,
            error)) {
        LogPrint(BCLog::GOBJECT,
                 "CGovernanceObject::SignPQ -- %s\n", error);
        return false;
    }

    llmq::pq::GovernanceAuthorization authorization;
    authorization.signed_height = signing_block.nHeight;
    authorization.signed_block_hash = signing_block.GetBlockHash();
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = global_key_version;
    const auto digest{llmq::pq::GetGovernanceAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, current_key,
        authorization, llmq::pq::GovernanceAuthPurpose::TRIGGER,
        GetSignatureHash())};
    if (!digest || !SignActiveMasternodeGovernanceTrigger(
                       pro_tx_hash, global_key_version, *digest,
                       authorization.signature) ||
        !llmq::pq::EncodeGovernanceAuthorization(authorization,
                                                  m_obj.vchSig)) {
        m_obj.vchSig.clear();
        return false;
    }
    return true;
}

bool CGovernanceObject::CheckPQSignature(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    // SYSCOIN: SLH verification must never inherit consensus/governance locks.
    AssertLockNotHeld(cs_main);
    if (governance) AssertLockNotHeld(governance->cs);
    AssertLockNotHeld(cs);

    return llmq::pq::VerifyGovernanceAuthorizationForBranch(
        validation_branch, validation_mn_list, m_obj.masternodeOutpoint,
        llmq::pq::GovernanceAuthPurpose::TRIGGER, GetSignatureHash(),
        m_obj.vchSig, error);
}

bool CGovernanceObject::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContextForBranch(
        validation_branch, validation_mn_list, m_obj.masternodeOutpoint,
        m_obj.vchSig, authorization, error);
}

bool CGovernanceObject::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistrySnapshot& current_snapshot,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContext(
        validation_branch, validation_mn_list, current_snapshot,
        m_obj.masternodeOutpoint, m_obj.vchSig, authorization, error);
}

bool CGovernanceObject::CheckPQAuthorizationContext(
    const CBlockIndex& validation_branch,
    const CDeterministicMNList& validation_mn_list,
    const llmq::pq::PQRegistryReadView& current_snapshot,
    std::string& error) const
{
    llmq::pq::GovernanceAuthorization authorization;
    return llmq::pq::CheckGovernanceAuthorizationContext(
        validation_branch, validation_mn_list, current_snapshot,
        m_obj.masternodeOutpoint, m_obj.vchSig, authorization, error);
}

/**
   Return the actual object from the vchData JSON structure.

   Returns an empty object on error.
 */
UniValue CGovernanceObject::GetJSONObject() const
{
    UniValue obj(UniValue::VOBJ);
    if (m_obj.vchData.empty()) {
        return obj;
    }

    UniValue objResult(UniValue::VOBJ);
    GetData(objResult);

    if (objResult.isObject()) {
        obj = objResult;
    } else {
        std::vector<UniValue> arr1 = objResult.getValues();
        std::vector<UniValue> arr2 = arr1.at(0).getValues();
        obj = arr2.at(1);
    }

    return obj;
}

/**
*   LoadData
*   --------------------------------------------------------
*
*   Attempt to load data from vchData
*
*/

void CGovernanceObject::LoadData()
{
    if (m_obj.vchData.empty()) {
        return;
    }

    try {
        // ATTEMPT TO LOAD JSON STRING FROM VCHDATA
        UniValue objResult(UniValue::VOBJ);
        GetData(objResult);
        LogPrint(BCLog::GOBJECT, "CGovernanceObject::LoadData -- GetDataAsPlainString = %s\n", GetDataAsPlainString());
        UniValue obj = GetJSONObject();
        m_obj.type = GovernanceObject(obj["type"].getInt<int>());
    } catch (std::exception& e) {
        fUnparsable = true;
        std::ostringstream ostr;
        ostr << "CGovernanceObject::LoadData Error parsing JSON"
             << ", e.what() = " << e.what();
        LogPrintf("%s\n", ostr.str());
        return;
    } catch (...) {
        fUnparsable = true;
        std::ostringstream ostr;
        ostr << "CGovernanceObject::LoadData Unknown Error parsing JSON";
        LogPrintf("%s\n", ostr.str());
        return;
    }
}

/**
*   GetData - Example usage:
*   --------------------------------------------------------
*
*   Decode governance object data into UniValue(VOBJ)
*
*/

void CGovernanceObject::GetData(UniValue& objResult) const
{
    UniValue o(UniValue::VOBJ);
    std::string s = GetDataAsPlainString();
    o.read(s);
    objResult = o;
}

/**
*   GetData - As
*   --------------------------------------------------------
*
*/
std::string CGovernanceObject::GetDataAsHexString() const
{
    return m_obj.GetDataAsHexString();
}

std::string CGovernanceObject::GetDataAsPlainString() const
{
    return m_obj.GetDataAsPlainString();
}

UniValue CGovernanceObject::ToJson() const
{
    return m_obj.ToJson();
}

void CGovernanceObject::UpdateLocalValidity(ChainstateManager &chainman, const CDeterministicMNList& tip_mn_list)
{
    AssertLockHeld(cs_main);
    // THIS DOES NOT CHECK COLLATERAL, THIS IS CHECKED UPON ORIGINAL ARRIVAL
    fCachedLocalValidity = IsValidLocally(chainman, tip_mn_list, strLocalValidityError, false);
}


bool CGovernanceObject::IsValidLocally(ChainstateManager &chainman, const CDeterministicMNList& tip_mn_list, std::string& strError, bool fCheckCollateral, bool fPQSignaturePreverified) const
{
    bool fMissingConfirmations = false;

    return IsValidLocally(chainman, tip_mn_list, strError,
                          fMissingConfirmations, fCheckCollateral,
                          fPQSignaturePreverified);
}

bool CGovernanceObject::IsValidLocally(ChainstateManager &chainman, const CDeterministicMNList& tip_mn_list, std::string& strError, bool& fMissingConfirmations, bool fCheckCollateral, bool fPQSignaturePreverified) const
{
    AssertLockHeld(cs_main);
    fMissingConfirmations = false;
    if (fUnparsable) {
        strError = "Object data unparsable";
        return false;
    }

    switch (GetObjectType()) {
    case GOVERNANCE_OBJECT_PROPOSAL: {
        CProposalValidator validator(GetDataAsHexString());
        // Note: It's ok to have expired proposals
        // they are going to be cleared by CGovernanceManager::CheckAndRemove()
        // TODO: should they be tagged as "expired" to skip vote downloading?
        if (!validator.Validate(false)) {
            strError = strprintf("Invalid proposal data, error messages: %s", validator.GetErrorMessages());
            return false;
        }
        if (fCheckCollateral && !IsCollateralValid(chainman, strError, fMissingConfirmations)) {
            strError = "Invalid proposal collateral";
            return false;
        }
        return true;
    }
    case GOVERNANCE_OBJECT_TRIGGER: {
        std::string strOutpoint = m_obj.masternodeOutpoint.ToStringShort();
        auto dmn = tip_mn_list.GetMNByCollateral(m_obj.masternodeOutpoint);
        if (!dmn) {
            strError = "Failed to find Masternode by UTXO, missing masternode=" + strOutpoint;
            return false;
        }

        // SYSCOIN: callers holding cs_main may only commit a trigger whose SLH
        // proof was verified before taking state locks.
        if (fCheckCollateral && !fPQSignaturePreverified) {
            strError = "trigger requires preverified SLH authorization";
            return false;
        }
        const CBlockIndex* validation_tip{chainman.ActiveTip()};
        const bool valid = validation_tip != nullptr &&
            CheckPQAuthorizationContext(*validation_tip, tip_mn_list,
                                        strError);
        if (!valid) {
            strError = "Invalid post-anchor SLH trigger authorization for " +
                       strOutpoint + ": " + strError;
            return false;
        }

        return true;
    }
    default: {
        strError = strprintf("Invalid object type %d", GetObjectType());
        return false;
    }
    }
}

CAmount CGovernanceObject::GetMinCollateralFee() const
{
    // Only 1 type has a fee for the moment but switch statement allows for future object types
    switch (GetObjectType()) {
        case GOVERNANCE_OBJECT_PROPOSAL: {
            return GOVERNANCE_PROPOSAL_FEE_TX;
        }
        case GOVERNANCE_OBJECT_TRIGGER: {
            return 0;
        }
        default: {
            return MAX_MONEY;
        }
    }
}

bool CGovernanceObject::IsCollateralValid(ChainstateManager &chainman, std::string& strError, bool& fMissingConfirmations) const
{
    AssertLockHeld(cs_main);
    strError = "";
    fMissingConfirmations = false;
    const uint256 nExpectedHash = GetHash();
    const uint256 nCollateralHash = GetCollateralHash();
    // RETRIEVE TRANSACTION IN QUESTION
    CTransactionRef txCollateral;
    uint32_t nBlockHeight;
    uint256 nBlockHash;
    // RETRIEVE TRANSACTION IN QUESTION
    if(!pblockindexdb->ReadBlockHeight(nCollateralHash, nBlockHeight)){	    
        
        strError = strprintf("Can't find collateral blockhash %s in block index", nCollateralHash.ToString());	
        LogPrint(BCLog::GOBJECT, "CGovernanceObject::IsCollateralValid -- %s\n", strError);	
        return false;   	
    }
    txCollateral = GetTransaction(chainman.ActiveChain()[nBlockHeight], nullptr, nCollateralHash, nBlockHash, chainman.m_blockman);
    if(!txCollateral) {
        strError = strprintf("Can't find collateral tx %s", nCollateralHash.ToString());
        LogPrint(BCLog::GOBJECT,"CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }
    int nConfirmationsIn = chainman.ActiveHeight() - nBlockHeight + 1;
    if (nBlockHash == uint256()) {
        strError = strprintf("Collateral tx %s is not mined yet", txCollateral->ToString());
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    if (txCollateral->vout.empty()) {
        strError = "tx vout is empty";
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    // LOOK FOR SPECIALIZED GOVERNANCE SCRIPT (PROOF OF BURN)

    CScript findScript;
    findScript << OP_RETURN << ToByteVector(nExpectedHash);

    CAmount nMinFee = GetMinCollateralFee();

    LogPrint(BCLog::GOBJECT, "CGovernanceObject::IsCollateralValid -- txCollateral->vout.size() = %s, findScript = %s, nMinFee = %lld\n",
                txCollateral->vout.size(), ScriptToAsmStr(findScript, false), nMinFee);

    bool foundOpReturn = false;
    for (const auto& output : txCollateral->vout) {
        LogPrint(BCLog::GOBJECT, "CGovernanceObject::IsCollateralValid -- txout = %s, output.nValue = %lld, output.scriptPubKey = %s\n",
                    output.ToString(), output.nValue, ScriptToAsmStr(output.scriptPubKey, false));
        if (output.scriptPubKey.IsUnspendable() && output.scriptPubKey == findScript && output.nValue >= nMinFee) {
            foundOpReturn = true;
        }
    }

    if (!foundOpReturn) {
        strError = strprintf("Couldn't find opReturn %s in %s", nExpectedHash.ToString(), txCollateral->ToString());
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);
        return false;
    }

    // GET CONFIRMATIONS FOR TRANSACTION


    if (nConfirmationsIn < GOVERNANCE_FEE_CONFIRMATIONS) {
        strError = strprintf("Collateral requires at least %d confirmations to be relayed throughout the network (it has only %d)", GOVERNANCE_FEE_CONFIRMATIONS, nConfirmationsIn);
        if (nConfirmationsIn >= GOVERNANCE_MIN_RELAY_FEE_CONFIRMATIONS) {
            fMissingConfirmations = true;
            strError += ", pre-accepted -- waiting for required confirmations";
        } else {
            strError += ", rejected -- try again later";
        }
        LogPrintf("CGovernanceObject::IsCollateralValid -- %s\n", strError);

        return false;
    }

    strError = "valid";
    return true;
}

int CGovernanceObject::CountMatchingVotes(vote_signal_enum_t eVoteSignalIn, vote_outcome_enum_t eVoteOutcomeIn) const
{
    LOCK(cs);

    int nCount = 0;
    for (const auto& votepair : mapCurrentMNVotes) {
        const vote_rec_t& recVote = votepair.second;
        auto it2 = recVote.mapInstances.find(eVoteSignalIn);
        if (it2 != recVote.mapInstances.end() && it2->second.eOutcome == eVoteOutcomeIn) {
            ++nCount;
        }
    }
    return nCount;
}

/**
*   Get specific vote counts for each outcome (funding, validity, etc)
*/

int CGovernanceObject::GetAbsoluteYesCount(vote_signal_enum_t eVoteSignalIn) const
{
    return GetYesCount(eVoteSignalIn) - GetNoCount(eVoteSignalIn);
}

int CGovernanceObject::GetAbsoluteNoCount(vote_signal_enum_t eVoteSignalIn) const
{
    return GetNoCount(eVoteSignalIn) - GetYesCount(eVoteSignalIn);
}

int CGovernanceObject::GetYesCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_YES);
}

int CGovernanceObject::GetNoCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_NO);
}

int CGovernanceObject::GetAbstainCount(vote_signal_enum_t eVoteSignalIn) const
{
    return CountMatchingVotes(eVoteSignalIn, VOTE_OUTCOME_ABSTAIN);
}

bool CGovernanceObject::GetCurrentMNVotes(const COutPoint& mnCollateralOutpoint, vote_rec_t& voteRecord) const
{
    LOCK(cs);

    auto it = mapCurrentMNVotes.find(mnCollateralOutpoint);
    if (it == mapCurrentMNVotes.end()) {
        return false;
    }
    voteRecord = it->second;
    return true;
}

void CGovernanceObject::Relay(PeerManager& peerman) const
{
    // Do not relay until fully synced
    if (!masternodeSync.IsSynced()) {
        LogPrint(BCLog::GOBJECT, "CGovernanceObject::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_GOVERNANCE_OBJECT, GetHash());
    peerman.RelayInv(inv);
}

void CGovernanceObject::UpdateSentinelVariables(
    const CDeterministicMNList& tip_mn_list,
    bool reset_vote_caused_deletion)
{
    // SET SENTINEL FLAGS TO FALSE

    fCachedFunding = false;
    fCachedValid = true; //default to valid
    fCachedEndorsed = false;
    fDirtyCache = false;

    if (reset_vote_caused_deletion && fCachedDeleteByVotes) {
        fCachedDelete = false;
        fCachedDeleteByVotes = false;
        nDeletionTime = 0;
    }

    // An empty valid roster must clear stale vote-derived state as well.
    int nWeightedMnCount = (int)tip_mn_list.GetValidMNsCount();
    if (nWeightedMnCount == 0) return;

    // CALCULATE THE MINIMUM VOTE COUNT REQUIRED FOR FULL SIGNAL

    int nAbsVoteReq = std::max(Params().GetConsensus().nGovernanceMinQuorum, nWeightedMnCount / 10);
    int nAbsDeleteReq = std::max(Params().GetConsensus().nGovernanceMinQuorum, (2 * nWeightedMnCount) / 3);

    // SET SENTINEL FLAGS TO TRUE IF MINIMUM SUPPORT LEVELS ARE REACHED
    // ARE ANY OF THESE FLAGS CURRENTLY ACTIVATED?

    if (GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING) >= nAbsVoteReq) fCachedFunding = true;
    if ((GetAbsoluteYesCount(VOTE_SIGNAL_DELETE) >= nAbsDeleteReq) && !fCachedDelete) {
        fCachedDelete = true;
        fCachedDeleteByVotes = true;
        if (nDeletionTime == 0) {
            nDeletionTime = GetTime<std::chrono::seconds>().count();
        }
    }
    if (GetAbsoluteYesCount(VOTE_SIGNAL_ENDORSED) >= nAbsVoteReq) fCachedEndorsed = true;

    if (GetAbsoluteNoCount(VOTE_SIGNAL_VALID) >= nAbsVoteReq) fCachedValid = false;
}
