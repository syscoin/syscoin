// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/deterministicmns.h>
#include <evo/specialtx.h>

#include <base58.h>
#include <chainparams.h>
#include <core_io.h>
#include <script/script.h>
#include <node/interface_ui.h>
#include <validation.h>
#include <validationinterface.h>

#include <llmq/quorums_commitment.h>
#include <llmq/quorums_utils.h>
#include <univalue.h>
#include <shutdown.h>
#include <common/args.h>
#include <logging.h>
#include <interfaces/chain.h>
#include <boost/range/irange.hpp>
bool fMasternodeMode = false;
int64_t DEFAULT_MAX_RECOVERED_SIGS_AGE = 60 * 60 * 24 * 7; // keep them for a week

std::unique_ptr<CDeterministicMNManager> deterministicMNManager;

uint64_t CDeterministicMN::GetInternalId() const
{
    // can't get it if it wasn't set yet
    assert(internalId != std::numeric_limits<uint64_t>::max());
    return internalId;
}

std::string CDeterministicMN::ToString() const
{
    return strprintf("CDeterministicMN(proTxHash=%s, collateralOutpoint=%s, nOperatorReward=%f, state=%s", proTxHash.ToString(), collateralOutpoint.ToStringShort(), (double)nOperatorReward / 100, pdmnState->ToString());
}

void CDeterministicMN::ToJson(interfaces::Chain& chain, UniValue& obj) const
{
    obj.clear();
    obj.setObject();

    UniValue stateObj;
    pdmnState->ToJson(stateObj);

    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", (int)collateralOutpoint.n);

    std::map<COutPoint, Coin> coins;
    coins[collateralOutpoint]; 
    chain.findCoins(coins);
    const Coin &coin = coins.at(collateralOutpoint);
    if (!coin.IsSpent()) {
        CTxDestination dest;
        if (ExtractDestination(coin.out.scriptPubKey, dest)) {
            obj.pushKV("collateralAddress", EncodeDestination(dest));
        }
    }

    obj.pushKV("operatorReward", (double)nOperatorReward / 100);
    obj.pushKV("state", stateObj);
}

bool CDeterministicMNList::IsMNValid(const uint256& proTxHash) const
{
    auto p = mnMap.find(proTxHash);
    if (p == nullptr) {
        return false;
    }
    return IsMNValid(**p);
}

bool CDeterministicMNList::IsMNPoSeBanned(const uint256& proTxHash) const
{
    auto p = mnMap.find(proTxHash);
    if (p == nullptr) {
        return false;
    }
    return IsMNPoSeBanned(**p);
}

bool CDeterministicMNList::IsMNValid(const CDeterministicMN& dmn)
{
    return !IsMNPoSeBanned(dmn);
}

bool CDeterministicMNList::IsMNPoSeBanned(const CDeterministicMN& dmn)
{
    return dmn.pdmnState->IsBanned();
}

CDeterministicMNCPtr CDeterministicMNList::GetMN(const uint256& proTxHash) const
{
    auto p = mnMap.find(proTxHash);
    if (p == nullptr) {
        return nullptr;
    }
    return *p;
}

CDeterministicMNCPtr CDeterministicMNList::GetValidMN(const uint256& proTxHash) const
{
    auto dmn = GetMN(proTxHash);
    if (dmn && !IsMNValid(*dmn)) {
        return nullptr;
    }
    return dmn;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByOperatorKey(const CBLSPublicKey& pubKey) const
{
    const auto it = ranges::find_if(mnMap,
                              [&pubKey](const auto& p){return p.second->pdmnState->pubKeyOperator.Get() == pubKey;});
    if (it == mnMap.end()) {
        return nullptr;
    }
    return it->second;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByCollateral(const COutPoint& collateralOutpoint) const
{
    return GetUniquePropertyMN(collateralOutpoint);
}

CDeterministicMNCPtr CDeterministicMNList::GetValidMNByCollateral(const COutPoint& collateralOutpoint) const
{
    auto dmn = GetMNByCollateral(collateralOutpoint);
    if (dmn && !IsMNValid(*dmn)) {
        return nullptr;
    }
    return dmn;
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByService(const CService& service) const
{
    return GetUniquePropertyMN(service);
}

CDeterministicMNCPtr CDeterministicMNList::GetMNByInternalId(uint64_t internalId) const
{
    auto proTxHash = mnInternalIdMap.find(internalId);
    if (!proTxHash) {
        return nullptr;
    }
    return GetMN(*proTxHash);
}

static int CompareByLastPaid_GetHeight(const CDeterministicMN& dmn)
{
    int height = dmn.pdmnState->nLastPaidHeight;
    if (dmn.pdmnState->nPoSeRevivedHeight != -1 && dmn.pdmnState->nPoSeRevivedHeight > height) {
        height = dmn.pdmnState->nPoSeRevivedHeight;
    } else if (height == 0) {
        height = dmn.pdmnState->nRegisteredHeight;
    }
    return height;
}

static bool CompareByLastPaid(const CDeterministicMN& _a, const CDeterministicMN& _b)
{
    int ah = CompareByLastPaid_GetHeight(_a);
    int bh = CompareByLastPaid_GetHeight(_b);
    if (ah == bh) {
        return _a.proTxHash < _b.proTxHash;
    } else {
        return ah < bh;
    }
}
static bool CompareByLastPaid(const CDeterministicMN* _a, const CDeterministicMN* _b)
{
    return CompareByLastPaid(*_a, *_b);
}

CDeterministicMNCPtr CDeterministicMNList::GetMNPayee() const
{
    if (mnMap.size() == 0) {
        return nullptr;
    }

    CDeterministicMNCPtr best;
    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        if (!best || CompareByLastPaid(dmn.get(), best.get())) {
            best = dmn;
        }
    });

    return best;
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::GetProjectedMNPayees(int nCount) const
{
    const size_t & validCount = GetValidMNsCount();
    if ((size_t)nCount > validCount) {
        nCount = validCount;
    }

    std::vector<CDeterministicMNCPtr> result;
    result.reserve(nCount);

    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        result.emplace_back(dmn);
    });
    std::sort(result.begin(), result.end(), [&](const CDeterministicMNCPtr& a, const CDeterministicMNCPtr& b) {
        return CompareByLastPaid(a.get(), b.get());
    });

    result.resize(nCount);

    return result;
}

std::vector<CDeterministicMNCPtr> CDeterministicMNList::CalculateQuorum(size_t maxSize, const uint256& modifier) const
{
    auto scores = CalculateScores(modifier);

    // sort is descending order
    std::sort(scores.rbegin(), scores.rend(), [](const std::pair<arith_uint256, CDeterministicMNCPtr>& a, const std::pair<arith_uint256, CDeterministicMNCPtr>& b) {
        if (a.first == b.first) {
            // this should actually never happen, but we should stay compatible with how the non-deterministic MNs did the sorting
            return a.second->collateralOutpoint < b.second->collateralOutpoint;
        }
        return a.first < b.first;
    });

    // take top maxSize entries and return it
    std::vector<CDeterministicMNCPtr> result;
    result.resize(std::min(maxSize, scores.size()));
    for (size_t i = 0; i < result.size(); i++) {
        result[i] = std::move(scores[i].second);
    }
    return result;
}

std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>> CDeterministicMNList::CalculateScores(const uint256& modifier) const
{
    std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>> scores;
    scores.reserve(GetAllMNsCount());
    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        if (dmn->pdmnState->confirmedHash.IsNull()) {
            // we only take confirmed MNs into account to avoid hash grinding on the ProRegTxHash to sneak MNs into a
            // future quorums
            return;
        }
        // calculate sha256(sha256(proTxHash, confirmedHash), modifier) per MN
        // Please note that this is not a double-sha256 but a single-sha256
        // The first part is already precalculated (confirmedHashWithProRegTxHash)
        // TODO When https://github.com/bitcoin/bitcoin/pull/13191 gets backported, implement something that is similar but for single-sha256
        uint256 h;
        CSHA256 sha256;
        sha256.Write(dmn->pdmnState->confirmedHashWithProRegTxHash.begin(), dmn->pdmnState->confirmedHashWithProRegTxHash.size());
        sha256.Write(modifier.begin(), modifier.size());
        sha256.Finalize(h.begin());

        scores.emplace_back(UintToArith256(h), dmn);
    });

    return scores;
}

int CDeterministicMNList::CalcMaxPoSePenalty() const
{
    // Maximum PoSe penalty is dynamic and equals the number of registered MNs
    // It's however at least 100.
    // This means that the max penalty is usually equal to a full payment cycle
    return std::max(100, (int)GetAllMNsCount());
}

int CDeterministicMNList::CalcPenalty(int percent) const
{
    assert(percent > 0);
    return (CalcMaxPoSePenalty() * percent) / 100;
}

void CDeterministicMNList::PoSePunish(const uint256& proTxHash, int penalty)
{
    assert(penalty > 0);

    auto dmn = GetMN(proTxHash);
    if (!dmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }

    int maxPenalty = CalcMaxPoSePenalty();

    auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
    newState->nPoSePenalty += penalty;
    newState->nPoSePenalty = std::min(maxPenalty, newState->nPoSePenalty);


    LogPrint(BCLog::MNLIST, "CDeterministicMNList::%s -- punished MN %s, penalty %d->%d (max=%d)\n",
                __func__, proTxHash.ToString(), dmn->pdmnState->nPoSePenalty, newState->nPoSePenalty, maxPenalty);
    

    if (newState->nPoSePenalty >= maxPenalty && !newState->IsBanned()) {
        if(!newState->vchNEVMAddress.empty()) {
            m_changed_nevm_address = true;
        }
        newState->BanIfNotBanned(nHeight);
        LogPrint(BCLog::MNLIST, "CDeterministicMNList::%s -- banned MN %s at height %d\n",
                    __func__, proTxHash.ToString(), nHeight);
    
    }
    UpdateMN(proTxHash, newState);
}

void CDeterministicMNList::PoSeDecrease(const CDeterministicMN& dmn)
{
    assert(dmn.pdmnState->nPoSePenalty > 0 && !dmn.pdmnState->IsBanned());

    auto newState = std::make_shared<CDeterministicMNState>(*dmn.pdmnState);
    newState->nPoSePenalty--;
    UpdateMN(dmn, newState);
}

void CDeterministicMNList::BuildDiff(const CDeterministicMNList& to, CDeterministicMNListDiff &diffRet, CDeterministicMNListNEVMAddressDiff &diffRetNEVMAddress) const
{
    std::unordered_map<uint256, NEVMDiffEntry, StaticSaltedHasher> nevmDiffMap;
  // Process MNs from the new list (adds and updates)
    to.ForEachMNShared(false, [&](const CDeterministicMNCPtr& toPtr) {
        auto fromPtr = GetMN(toPtr->proTxHash);
        if (fromPtr == nullptr) {
            // Masternode is newly added.
            if (!toPtr->pdmnState->vchNEVMAddress.empty()) {
                NEVMDiffEntry entry;
                entry.type = NEVMDiffType::Added;
                entry.newAddress = toPtr->pdmnState->vchNEVMAddress;
                entry.collateralHeight = toPtr->pdmnState->nCollateralHeight;
                nevmDiffMap[toPtr->proTxHash] = entry;
            }
            diffRet.addedMNs.emplace_back(toPtr);
        } else if (fromPtr != toPtr || fromPtr->pdmnState != toPtr->pdmnState) {
            // MN exists in both lists but has been updated.
            CDeterministicMNStateDiff stateDiff(*fromPtr->pdmnState, *toPtr->pdmnState);
            if(stateDiff.fields) {
                if (stateDiff.fields & CDeterministicMNStateDiff::Field_vchNEVMAddress) {
                    NEVMDiffEntry entry;
                    if (toPtr->pdmnState->vchNEVMAddress.empty()) {
                        // Address was removed.
                        entry.type = NEVMDiffType::Removed;
                        entry.oldAddress = fromPtr->pdmnState->vchNEVMAddress;
                    } else if (fromPtr->pdmnState->vchNEVMAddress.empty()) {
                        // Address was added.
                        entry.type = NEVMDiffType::Added;
                        entry.newAddress = toPtr->pdmnState->vchNEVMAddress;
                        entry.collateralHeight = toPtr->pdmnState->nCollateralHeight;
                    } else {
                        // Address was updated.
                        entry.type = NEVMDiffType::Updated;
                        entry.oldAddress = fromPtr->pdmnState->vchNEVMAddress;
                        entry.newAddress = toPtr->pdmnState->vchNEVMAddress;
                    }
                    nevmDiffMap[toPtr->proTxHash] = entry;
                }
                diffRet.updatedMNs.emplace(toPtr->GetInternalId(), std::move(stateDiff));
            }
        }
    });

    // Process removals from the old list.
    ForEachMN(false, [&](auto& fromPtr) {
        auto toPtr = to.GetMN(fromPtr.proTxHash);
        if (toPtr == nullptr) {
            // Masternode removed entirely.
            if (!fromPtr.pdmnState->vchNEVMAddress.empty()) {
                NEVMDiffEntry entry;
                entry.type = NEVMDiffType::Removed;
                entry.oldAddress = fromPtr.pdmnState->vchNEVMAddress;
                nevmDiffMap[fromPtr.proTxHash] = entry;
            }
            diffRet.removedMns.emplace(fromPtr.GetInternalId());
        } else if (toPtr->pdmnState->vchNEVMAddress.empty() && !fromPtr.pdmnState->vchNEVMAddress.empty()) {
            // Masternode still exists but its NEVM address was cleared.
            NEVMDiffEntry entry;
            entry.type = NEVMDiffType::Removed;
            entry.oldAddress = fromPtr.pdmnState->vchNEVMAddress;
            nevmDiffMap[fromPtr.proTxHash] = entry;
        }
    });

    // Now convert the deduplicated map into the diff vectors.
    for (const auto& pair : nevmDiffMap) {
        const NEVMDiffEntry& entry = pair.second;
        switch (entry.type) {
            case NEVMDiffType::Added:
                diffRetNEVMAddress.addedMNNEVM.emplace_back(entry.newAddress, entry.collateralHeight);
                break;
            case NEVMDiffType::Updated:
                diffRetNEVMAddress.updatedMNNEVM.emplace_back(entry.oldAddress, entry.newAddress);
                break;
            case NEVMDiffType::Removed:
                diffRetNEVMAddress.removedMNNEVM.emplace_back(entry.oldAddress);
                break;
            default:
                break;
        }
    }

    // added MNs need to be sorted by internalId so that these are added in correct order when the diff is applied later
    // otherwise internalIds will not match with the original list
    std::sort(diffRet.addedMNs.begin(), diffRet.addedMNs.end(), [](const CDeterministicMNCPtr& a, const CDeterministicMNCPtr& b) {
        return a->GetInternalId() < b->GetInternalId();
    });
}

CDeterministicMNList CDeterministicMNList::ApplyDiff(const CBlockIndex* pindex, const CDeterministicMNListDiff& diff) const
{
    CDeterministicMNList result = *this;
    result.blockHash = pindex->GetBlockHash();
    result.nHeight = pindex->nHeight;

    for (const auto& id : diff.removedMns) {
        auto dmn = result.GetMNByInternalId(id);
        if (!dmn) {
            throw(std::runtime_error(strprintf("%s: can't find a removed masternode, id=%d", __func__, id)));
        }
        result.RemoveMN(dmn->proTxHash);
    }
    for (const auto& dmn : diff.addedMNs) {
        result.AddMN(dmn);
    }
    for (const auto& p : diff.updatedMNs) {
        auto dmn = result.GetMNByInternalId(p.first);
        result.UpdateMN(*dmn, p.second);
    }

    return result;
}

void CDeterministicMNList::AddMN(const CDeterministicMNCPtr& dmn, bool fBumpTotalCount)
{
    assert(dmn != nullptr);

    if (mnMap.find(dmn->proTxHash)) {
        throw(std::runtime_error(strprintf("%s: Can't add a masternode with a duplicate proTxHash=%s", __func__, dmn->proTxHash.ToString())));
    }
    if (mnInternalIdMap.find(dmn->GetInternalId())) {
        throw(std::runtime_error(strprintf("%s: Can't add a masternode with a duplicate internalId=%d", __func__, dmn->GetInternalId())));
    }

    // All mnUniquePropertyMap's updates must be atomic.
    // Using this temporary map as a checkpoint to rollback to in case of any issues.
    decltype(mnUniquePropertyMap) mnUniquePropertyMapSaved = mnUniquePropertyMap;

    if (!AddUniqueProperty(*dmn, dmn->collateralOutpoint)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate collateralOutpoint=%s", __func__,
                dmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort())));
    }
    if (dmn->pdmnState->addr != CService() && !AddUniqueProperty(*dmn, dmn->pdmnState->addr)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate address=%s", __func__,
                dmn->proTxHash.ToString(), dmn->pdmnState->addr.ToStringAddrPort())));
    }
    if (!AddUniqueProperty(*dmn, dmn->pdmnState->keyIDOwner)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate keyIDOwner=%s", __func__,
                dmn->proTxHash.ToString(), EncodeDestination(WitnessV0KeyHash(dmn->pdmnState->keyIDOwner)))));
    }
    if (dmn->pdmnState->pubKeyOperator.Get().IsValid() && !AddUniqueProperty(*dmn, dmn->pdmnState->pubKeyOperator)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate pubKeyOperator=%s", __func__,
                dmn->proTxHash.ToString(), dmn->pdmnState->pubKeyOperator.Get().ToString())));
    }

    mnMap = mnMap.set(dmn->proTxHash, dmn);
    mnInternalIdMap = mnInternalIdMap.set(dmn->GetInternalId(), dmn->proTxHash);
    if (fBumpTotalCount) {
        // nTotalRegisteredCount acts more like a checkpoint, not as a limit,
        nTotalRegisteredCount = std::max(dmn->GetInternalId() + 1, (uint64_t)nTotalRegisteredCount);
    }
}

void CDeterministicMNList::UpdateMN(const CDeterministicMN& oldDmn, const std::shared_ptr<const CDeterministicMNState>& pdmnState)
{
    auto dmn = std::make_shared<CDeterministicMN>(oldDmn);
    auto oldState = dmn->pdmnState;
    dmn->pdmnState = pdmnState;

    // All mnUniquePropertyMap's updates must be atomic.
    // Using this temporary map as a checkpoint to rollback to in case of any issues.
    decltype(mnUniquePropertyMap) mnUniquePropertyMapSaved = mnUniquePropertyMap;

    if (!UpdateUniqueProperty(*dmn, oldState->addr, pdmnState->addr)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't update a masternode %s with a duplicate address=%s", __func__,
                oldDmn.proTxHash.ToString(), pdmnState->addr.ToStringAddrPort())));
    }
    if (!UpdateUniqueProperty(*dmn, oldState->keyIDOwner, pdmnState->keyIDOwner)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't update a masternode %s with a duplicate keyIDOwner=%s", __func__,
                oldDmn.proTxHash.ToString(), EncodeDestination(WitnessV0KeyHash(pdmnState->keyIDOwner)))));
    }
    if (!UpdateUniqueProperty(*dmn, oldState->pubKeyOperator, pdmnState->pubKeyOperator)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't update a masternode %s with a duplicate pubKeyOperator=%s", __func__,
                oldDmn.proTxHash.ToString(), pdmnState->pubKeyOperator.Get().ToString())));
    }
    if (!UpdateUniqueProperty(*dmn, oldState->vchNEVMAddress, pdmnState->vchNEVMAddress)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't update a masternode %s with a duplicate vchNEVMAddress=%s", __func__,
                oldDmn.proTxHash.ToString(), HexStr(pdmnState->vchNEVMAddress))));
    }
    mnMap = mnMap.set(oldDmn.proTxHash, dmn);
}

void CDeterministicMNList::UpdateMN(const uint256& proTxHash, const std::shared_ptr<const CDeterministicMNState>& pdmnState)
{
    auto oldDmn = mnMap.find(proTxHash);
    if (!oldDmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }
    UpdateMN(**oldDmn, pdmnState);
}

void CDeterministicMNList::UpdateMN(const CDeterministicMN& oldDmn, const CDeterministicMNStateDiff& stateDiff)
{
    auto oldState = oldDmn.pdmnState;
    auto newState = std::make_shared<CDeterministicMNState>(*oldState);
    stateDiff.ApplyToState(*newState);
    UpdateMN(oldDmn, newState);
}

void CDeterministicMNList::RemoveMN(const uint256& proTxHash)
{
    auto dmn = GetMN(proTxHash);
    if (!dmn) {
        throw(std::runtime_error(strprintf("%s: Can't find a masternode with proTxHash=%s", __func__, proTxHash.ToString())));
    }

    // All mnUniquePropertyMap's updates must be atomic.
    // Using this temporary map as a checkpoint to rollback to in case of any issues.
    decltype(mnUniquePropertyMap) mnUniquePropertyMapSaved = mnUniquePropertyMap;

    if (!DeleteUniqueProperty(*dmn, dmn->collateralOutpoint)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a collateralOutpoint=%s", __func__,
                proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort())));
    }
    if (dmn->pdmnState->addr != CService() && !DeleteUniqueProperty(*dmn, dmn->pdmnState->addr)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a address=%s", __func__,
                proTxHash.ToString(), dmn->pdmnState->addr.ToStringAddrPort())));
    }
    if (!DeleteUniqueProperty(*dmn, dmn->pdmnState->keyIDOwner)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a keyIDOwner=%s", __func__,
                proTxHash.ToString(), EncodeDestination(WitnessV0KeyHash(dmn->pdmnState->keyIDOwner)))));
    }
    if (dmn->pdmnState->pubKeyOperator.Get().IsValid() && !DeleteUniqueProperty(*dmn, dmn->pdmnState->pubKeyOperator)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a pubKeyOperator=%s", __func__,
                proTxHash.ToString(), dmn->pdmnState->pubKeyOperator.Get().ToString())));
    }

    mnMap = mnMap.erase(proTxHash);
    mnInternalIdMap = mnInternalIdMap.erase(dmn->GetInternalId());
}

std::string CDeterministicMNListNEVMAddressDiff::ToString() const {
    std::string addedStr, updatedStr, removedStr;

    for (const auto& entry : addedMNNEVM) {
        addedStr += strprintf("(Address=%s, CollateralHeight=%d) ", HexStr(entry.first), entry.second);
    }

    for (const auto& entry : updatedMNNEVM) {
        updatedStr += strprintf("(OldAddress=%s, NewAddress=%s) ", HexStr(entry.first), HexStr(entry.second));
    }

    for (const auto& entry : removedMNNEVM) {
        removedStr += strprintf("(Address=%s) ", HexStr(entry));
    }

    return strprintf(
        "CDeterministicMNListNEVMAddressDiff(Added=%s, Updated=%s, Removed=%s)",
        addedStr.empty() ? "None" : addedStr,
        updatedStr.empty() ? "None" : updatedStr,
        removedStr.empty() ? "None" : removedStr
    );
}

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& _state, const CCoinsViewCache& view, const llmq::CFinalCommitmentTxPayload &qcTx, CDeterministicMNListNEVMAddressDiff &diffNEVM, bool fJustCheck, bool ibd)
{
    const auto& consensusParams = Params().GetConsensus();
    bool fDIP0003Active = pindex->nHeight >= consensusParams.DIP0003Height;
    bool fNexusActive = pindex->nHeight >= consensusParams.nNexusStartBlock;
    if (!fDIP0003Active) {
        return true;
    }

    CDeterministicMNList oldList, newList;
    CDeterministicMNListDiff diff;

    int nHeight = pindex->nHeight;
    try {

        if (!BuildNewListFromBlock(block, pindex->pprev, _state, view, newList, oldList, qcTx)) {
            // pass the state returned by the function above
            return false;
        }
        if (fJustCheck) {
            return true;
        }

        if (newList.GetHeight() == -1) {
            newList.SetHeight(nHeight);
        }

        newList.SetBlockHash(pindex->GetBlockHash());
        {
            LOCK(cs);
            tipIndex = pindex;
        }
        // this call runs through every MN so its expensive only do it when needed
        // for NEVM we need to build and make a consistent list thats accessible via a precompile (m_changed_nevm_address will also tell us when NEVM address changed)
        if(!ibd || (fNEVMConnection && fNexusActive && newList.m_changed_nevm_address)) {
            oldList.BuildDiff(newList, diff, diffNEVM);
        }
        {
            LOCK(cs);
            m_evoDb->WriteCache(newList.GetBlockHash(), ibd? std::move(newList): newList);
        }
       
    } catch (const std::exception& e) {
        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- internal error: %s\n", __func__, e.what());
        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-dmn-block");
    }
    if(!ibd) {
        if (diff.HasChanges()) {
            GetMainSignals().NotifyMasternodeListChanged(false, oldList, diff);
        }
        // always update interface for payment detail changes
        uiInterface.NotifyMasternodeListChanged(newList);
    }
    return true;
}


bool CDeterministicMNManager::UndoBlock(const CBlockIndex* pindex, CDeterministicMNListNEVMAddressDiff &inversedDiffNEVMAddress)
{
    uint256 blockHash = pindex->GetBlockHash();

    CDeterministicMNList curList;
    CDeterministicMNList prevList;
    bool readCache = false;
    {
        LOCK(cs);
        readCache = m_evoDb->ReadCache(blockHash, curList);
    }
    if(readCache) {
        prevList = GetListForBlockInternal(pindex->pprev);
        {
            LOCK(cs);
            tipIndex = pindex->pprev;
        }
        CDeterministicMNListDiff inversedDiff;
        curList.BuildDiff(prevList, inversedDiff, inversedDiffNEVMAddress);
        if(inversedDiff.HasChanges()) {
            GetMainSignals().NotifyMasternodeListChanged(true, prevList, inversedDiff);
        }
        // SYSCOIN always update interface
        uiInterface.NotifyMasternodeListChanged(prevList);
    }
    return true;
}

bool CDeterministicMNManager::BuildNewListFromBlock(const CBlock& block, const CBlockIndex* pindexPrev, BlockValidationState& _state, const CCoinsViewCache& view, CDeterministicMNList& mnListRet, CDeterministicMNList& oldList, const llmq::CFinalCommitmentTxPayload &qcTxIn)
{

    int nHeight = pindexPrev->nHeight + 1;

    oldList = GetListForBlock(pindexPrev);
    CDeterministicMNList newList = oldList;
    newList.SetBlockHash(uint256()); // we can't know the final block hash, so better not return a (invalid) block hash
    newList.SetHeight(nHeight);

    bool decreasePoSE = false;
    if(!fRegTest) {
        // in sys we only run one quorum so we need to be more sure in this service we will catch a bad MN within around 1 payment round
        if((nHeight % 3) == 0) {
            decreasePoSE = true;
        }
    } else {
        decreasePoSE = true;
    }
    auto payee = oldList.GetMNPayee();
    // at least 2 rounds of payments before registered MN's gets put in list
    const size_t &mnCountThreshold = oldList.GetValidMNsCount()*2;
    // we iterate the oldList here and update the newList
    // this is only valid as long these have not diverged at this point, which is the case as long as we don't add
    // code above this loop that modifies newList
    std::vector<CDeterministicMNCPtr> toDecrease;
    toDecrease.reserve(oldList.GetAllMNsCount() / 10);
    oldList.ForEachMNShared(false, [&decreasePoSE, &oldList,  &toDecrease, &mnCountThreshold, &pindexPrev, &newList](const CDeterministicMNCPtr& dmn) {
        if (dmn->pdmnState->confirmedHash.IsNull()) {
            // this works on the previous block, so confirmation will happen one block after mnCountThreshold
            // has been reached, but the block hash will then point to the block at mnCountThreshold
            const size_t nConfirmations = pindexPrev->nHeight - dmn->pdmnState->nRegisteredHeight;
            if (nConfirmations >= mnCountThreshold) {
                auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
                newState->UpdateConfirmedHash(dmn->proTxHash, pindexPrev->GetBlockHash());
                newList.UpdateMN(dmn->proTxHash, newState);
            }
        }
        if(decreasePoSE && oldList.IsMNValid(*dmn)) {
            if (dmn->pdmnState->nPoSePenalty > 0) {
                toDecrease.emplace_back(dmn);
            }
        }
    });
    // decrease PoSe ban score
    if(decreasePoSE) {
        DecreasePoSePenalties(newList, toDecrease);
    }

    if(!qcTxIn.commitment.IsNull()) {
        const auto& params = Params().GetConsensus().llmqTypeChainLocks;
        uint32_t quorumHeight = qcTxIn.nHeight - (qcTxIn.nHeight % params.dkgInterval);
        auto quorumIndex = pindexPrev->GetAncestor(quorumHeight);
        if (!quorumIndex || quorumIndex->GetBlockHash() != qcTxIn.commitment.quorumHash) {
            // we should actually never get into this case as validation should have caught it...but let's be sure
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-qc-quorum-hash");
        }
        HandleQuorumCommitment(qcTxIn.commitment, quorumIndex, newList);            
    }
    
    // for all other tx's MN register/update tx handling
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        switch(tx.nVersion) {
            case(SYSCOIN_TX_VERSION_MN_REGISTER): {
                CProRegTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
                }

                auto dmn = std::make_shared<CDeterministicMN>(newList.GetTotalRegisteredCount());
                dmn->proTxHash = tx.GetHash();

                // collateralOutpoint is either pointing to an external collateral or to the ProRegTx itself
                if (proTx.collateralOutpoint.hash.IsNull()) {
                    dmn->collateralOutpoint = COutPoint(tx.GetHash(), proTx.collateralOutpoint.n);
                } else {
                    dmn->collateralOutpoint = proTx.collateralOutpoint;
                }

                Coin coin;
                if (!proTx.collateralOutpoint.hash.IsNull() && (!view.GetCoin(dmn->collateralOutpoint, coin) || coin.IsSpent() || coin.out.nValue != nMNCollateralRequired)) {
                    // should actually never get to this point as CheckProRegTx should have handled this case.
                    // We do this additional check nevertheless to be 100% sure
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-collateral");
                }

                auto replacedDmn = newList.GetMNByCollateral(dmn->collateralOutpoint);
                if (replacedDmn != nullptr) {
                    // This might only happen with a ProRegTx that refers an external collateral
                    // In that case the new ProRegTx will replace the old one. This means the old one is removed
                    // and the new one is added like a completely fresh one, which is also at the bottom of the payment list
                    if(!replacedDmn->pdmnState->vchNEVMAddress.empty()) {
                        newList.m_changed_nevm_address = true;
                    }
                    newList.RemoveMN(replacedDmn->proTxHash);
                    LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s removed from list because collateral was used for a new ProRegTx. collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                                __func__, replacedDmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(), nHeight, newList.GetAllMNsCount());
                }

                if (newList.HasUniqueProperty(proTx.addr)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-addr");
                }
                if (newList.HasUniqueProperty(proTx.keyIDOwner) || newList.HasUniqueProperty(proTx.pubKeyOperator)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-key");
                }
                dmn->nOperatorReward = proTx.nOperatorReward;
                dmn->pdmnState = std::make_shared<CDeterministicMNState>(proTx);
                auto dmnState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
                dmnState->nRegisteredHeight = nHeight;
                // if using external collateral,  height from when collateral was created
                if(!proTx.collateralOutpoint.hash.IsNull())
                    dmnState->nCollateralHeight = coin.nHeight;
                else
                    dmnState->nCollateralHeight = nHeight;

                if (proTx.addr == CService()) {
                    // start in banned pdmnState as we need to wait for a ProUpServTx
                    if(!dmnState->vchNEVMAddress.empty()) {
                        newList.m_changed_nevm_address = true;
                    }
                    dmnState->BanIfNotBanned(nHeight);
                }
                dmn->pdmnState = dmnState;

                newList.AddMN(dmn);
                LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s added at height %d: %s\n",
                        __func__, tx.GetHash().ToString(), nHeight, proTx.ToString());
                break;
            } 
            case(SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE): {
                CProUpServTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
                }

                if (newList.HasUniqueProperty(proTx.addr) && newList.GetUniquePropertyMN(proTx.addr)->proTxHash != proTx.proTxHash) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-addr");
                }

                CDeterministicMNCPtr dmn = newList.GetMN(proTx.proTxHash);
                if (!dmn) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
                }
                auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
                newState->addr = proTx.addr;
                newState->scriptOperatorPayout = proTx.scriptOperatorPayout;
                // Validate NEVM address only if non-empty
                if (!proTx.vchNEVMAddress.empty()) {
                    if (proTx.vchNEVMAddress.size() != 20) {
                        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-invalid-nevmaddress-size");
                    }
                    if (newList.HasUniqueProperty(proTx.vchNEVMAddress) && 
                        newList.GetUniquePropertyMN(proTx.vchNEVMAddress)->proTxHash != proTx.proTxHash) {
                        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-dup-nevm-address");
                    }
                }
                // Always handle NEVM address changes
                if (newState->vchNEVMAddress != proTx.vchNEVMAddress) {
                    if (newState->confirmedHash.IsNull()) {
                        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-unconfirmed-nevm-address");
                    }
                    if(newState->IsBanned()) {
                        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-banned-nevm-address");
                    }
                    newState->m_changed_nevm_address = true;
                    newState->vchNEVMAddress = proTx.vchNEVMAddress;
                }
                if (newState->IsBanned()) {
                    // only revive when all keys are set
                    if (newState->pubKeyOperator.Get().IsValid() && !newState->keyIDVoting.IsNull() && !newState->keyIDOwner.IsNull()) {
                        newState->Revive(nHeight);
                        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s revived at height %d\n",
                                __func__, proTx.proTxHash.ToString(), nHeight);
                    }
                } 
                
                newList.UpdateMN(proTx.proTxHash, newState);
                LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s updated at height %d: %s\n",
                        __func__, proTx.proTxHash.ToString(), nHeight, proTx.ToString());
                break;
            } 
            case(SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR): {
                CProUpRegTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
                }
            
                CDeterministicMNCPtr dmn = newList.GetMN(proTx.proTxHash);
                if (!dmn) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
                }
            
            
                auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
            
                // Handle pubKeyOperator changes
                if (newState->pubKeyOperator != proTx.pubKeyOperator) {
                    newState->ResetOperatorFields();
                    if(!newState->vchNEVMAddress.empty()) {
                        newList.m_changed_nevm_address = true;
                    }
                    newState->BanIfNotBanned(nHeight);
                    newState->nVersion = proTx.nVersion;
                    newState->pubKeyOperator = proTx.pubKeyOperator;
                }
            
                newState->keyIDVoting = proTx.keyIDVoting;
                newState->scriptPayout = proTx.scriptPayout;
                newList.UpdateMN(proTx.proTxHash, newState);
            
                LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s updated at height %d: %s\n",
                         __func__, proTx.proTxHash.ToString(), nHeight, proTx.ToString());
                break;
            }            
            case(SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE): {
                CProUpRevTx proTx;
                if (!GetTxPayload(tx, proTx)) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-payload");
                }

                CDeterministicMNCPtr dmn = newList.GetMN(proTx.proTxHash);
                if (!dmn) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-protx-hash");
                }
                auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
                newState->ResetOperatorFields();
                if(!newState->vchNEVMAddress.empty()) {
                    newList.m_changed_nevm_address = true;
                }
                newState->BanIfNotBanned(nHeight);
                newState->nRevocationReason = proTx.nReason;
                newList.UpdateMN(proTx.proTxHash, newState);
                LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s revoked operator key at height %d: %s\n",
                        __func__, proTx.proTxHash.ToString(), nHeight, proTx.ToString());
                break; 
            }
        }
    }

    // we skip the coinbase
    for (int i = 1; i < (int)block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        // check if any existing MN collateral is spent by this transaction
        for (const auto& in : tx.vin) {
            auto dmn = newList.GetMNByCollateral(in.prevout);
            if (dmn && dmn->collateralOutpoint == in.prevout) {
                if(!dmn->pdmnState->vchNEVMAddress.empty()) {
                    newList.m_changed_nevm_address = true;
                }
                newList.RemoveMN(dmn->proTxHash);
                LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- MN %s removed from list because collateral was spent. collateralOutpoint=%s, nHeight=%d, mapCurMNs.allMNsCount=%d\n",
                              __func__, dmn->proTxHash.ToString(), dmn->collateralOutpoint.ToStringShort(), nHeight, newList.GetAllMNsCount());
            }
        }
    }
    
    // The payee for the current block was determined by the previous block's list, but it might have disappeared in the
    // current block. We still pay that MN one last time however.
    if (payee && newList.HasMN(payee->proTxHash)) {
        auto newState = std::make_shared<CDeterministicMNState>(*newList.GetMN(payee->proTxHash)->pdmnState);
        newState->nLastPaidHeight = nHeight;
        newList.UpdateMN(payee->proTxHash, newState);
    }

    mnListRet = std::move(newList);
    return true;
}

void CDeterministicMNManager::HandleQuorumCommitment(const llmq::CFinalCommitment& qc, const CBlockIndex* pQuorumBaseBlockIndex, CDeterministicMNList& mnList)
{
    // The commitment has already been validated at this point, so it's safe to use members of it
    auto members = llmq::CLLMQUtils::GetAllQuorumMembers(pQuorumBaseBlockIndex);

    for (size_t i = 0; i < members.size(); i++) {
        if (!mnList.HasMN(members[i]->proTxHash)) {
            continue;
        }
        if (!qc.validMembers[i]) {
            // punish MN for failed DKG participation
            // The idea is to immediately ban a MN when it fails 2 DKG sessions with only a few blocks in-between
            // If there were enough blocks between failures, the MN has a chance to recover as he reduces his penalty by 1 every block
            // If it however fails 3 times in the timespan of a single payment cycle, it should definitely get banned
            mnList.PoSePunish(members[i]->proTxHash, mnList.CalcPenalty(66));
        }
    }
}

void CDeterministicMNManager::DecreasePoSePenalties(CDeterministicMNList& mnList, const std::vector<CDeterministicMNCPtr> &toDecrease)
{
    for (const CDeterministicMNCPtr& dmnPtr : toDecrease) {
        mnList.PoSeDecrease(*dmnPtr);
    }
}

const CDeterministicMNList CDeterministicMNManager::GetListForBlockInternal(const CBlockIndex* pindex)
{
    CDeterministicMNList snapshot;
    const auto& consensusParams = Params().GetConsensus();
    bool fDIP0003Active = pindex->nHeight >= consensusParams.DIP0003Height;
    if (!fDIP0003Active) {
        return snapshot;
    }
    {
        LOCK(cs);
        if (!m_evoDb->ReadCache(pindex->GetBlockHash(), snapshot)) {
            snapshot = CDeterministicMNList(pindex->GetBlockHash(), pindex->nHeight, 0);
            m_evoDb->WriteCache(pindex->GetBlockHash(), snapshot);
            LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- initial snapshot. blockHash=%s nHeight=%d\n", __func__,
                        snapshot.GetBlockHash().ToString(), snapshot.GetHeight());
            return snapshot;
        }
    }
    assert(snapshot.GetHeight() != -1);
    return snapshot;
}
const CDeterministicMNList CDeterministicMNManager::GetListForBlock(const CBlockIndex* pindex) {
    return GetListForBlockInternal(pindex);
};
const CDeterministicMNList CDeterministicMNManager::GetListAtChainTip()
{
    const CBlockIndex* pindex;
    {
        LOCK(cs);
        pindex = tipIndex;
    }
    if (!pindex) {
        return CDeterministicMNList();
    }
    return GetListForBlockInternal(pindex);
}

void CDeterministicMNManager::UpdatedBlockTip(const CBlockIndex* pindex) {
    WITH_LOCK(cs, tipIndex = pindex;);
}

bool CDeterministicMNManager::IsProTxWithCollateral(const CTransactionRef& tx, uint32_t n)
{
    if (tx->nVersion != SYSCOIN_TX_VERSION_MN_REGISTER) {
        return false;
    }
    CProRegTx proTx;
    if (!GetTxPayload(*tx, proTx)) {
        return false;
    }

    if (!proTx.collateralOutpoint.hash.IsNull()) {
        return false;
    }
    if (proTx.collateralOutpoint.n >= tx->vout.size() || proTx.collateralOutpoint.n != n) {
        return false;
    }
    if (tx->vout[n].nValue != nMNCollateralRequired) {
        return false;
    }
    return true;
}

bool CDeterministicMNManager::IsDIP3Enforced(int nHeight)
{
    return nHeight >= Params().GetConsensus().DIP0003EnforcementHeight;
}

void CDeterministicMNManager::DoMaintenance() {
    LOCK(cs);
    if (m_evoDb->IsCacheFull()) {
        DBParams db_params = m_evoDb->GetDBParams();
        // Create copies of the current caches
        std::unordered_map<uint256, CDeterministicMNList> mapCacheCopy = m_evoDb->GetMapCacheCopy();
        std::unordered_set<uint256> eraseCacheCopy = m_evoDb->GetEraseCacheCopy();

        db_params.wipe_data = true; // Set the wipe_data flag to true
        m_evoDb.reset(); // Destroy the current instance
        m_evoDb = std::make_unique<CEvoDB<uint256, CDeterministicMNList>>(db_params, LIST_CACHE_SIZE);
        // Restore the caches from the copies
        m_evoDb->RestoreCaches(mapCacheCopy, eraseCacheCopy);
        LogPrintf("CDeterministicMNManager::DoMaintenance Database successfully wiped and recreated.\n");
    }
}
bool CDeterministicMNManager::FlushCacheToDisk() {
    DoMaintenance();
    {
        LOCK(cs);
        return m_evoDb->FlushCacheToDisk();
    }
}
