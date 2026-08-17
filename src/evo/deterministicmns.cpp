// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/deterministicmns.h>
#include <evo/specialtx.h>

#include <base58.h>
#include <chainparams.h>
#include <core_io.h>
#include <consensus/pq_migration.h>
#include <script/script.h>
#include <node/interface_ui.h>
#include <validation.h>
#include <validationinterface.h>

#include <univalue.h>
#include <shutdown.h>
#include <common/args.h>
#include <logging.h>
#include <interfaces/chain.h>
#include <llmq/quorums_commitment.h>
#include <util/fs.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <chrono>

namespace {
constexpr std::string_view PQ_LEGACY_STATE_DOMAIN{"SYS_PQ_LEGACY_DMN_STATE_V1"};

DBParams MakePQRegistryDBParams(DBParams params)
{
    if (params.path.empty()) {
        params.path = "evodb_pq_registry";
    } else {
        const std::string sibling_name =
            fs::PathToString(params.path.filename()) + "_pq_registry";
        params.path = params.path.parent_path() / sibling_name;
    }
    // SYSCOIN: PQRegistryManager creates two LevelDBs from this budget.
    params.cache_bytes = std::max<std::size_t>(1, params.cache_bytes / 2);
    return params;
}

std::optional<uint256> EmptyPQRegistryStateRoot(const uint256& genesis_hash)
{
    llmq::pq::PQRegistrySnapshot empty;
    return empty.RecomputeConsensusStateRoot(genesis_hash);
}

llmq::pq::PQRegistryCallbacks MakePQRegistryCallbacks(
    const CDeterministicMNList& before,
    const CDeterministicMNList& after,
    const uint256& genesis_hash)
{
    llmq::pq::PQRegistryCallbacks callbacks;
    callbacks.dmn_exists_before = [&before](const uint256& pro_tx_hash) {
        return before.HasMN(pro_tx_hash);
    };
    callbacks.dmn_exists_after = [&after](const uint256& pro_tx_hash) {
        return after.HasMN(pro_tx_hash);
    };
    callbacks.verify_initial_owner_authorization =
        [&before, genesis_hash](
            const llmq::pq::GlobalKeyTxPayload& payload,
            const uint256& expected_authorization_hash) {
            const auto dmn = before.GetMN(payload.pro_tx_hash);
            const auto actual_authorization_hash =
                llmq::pq::GetGlobalOwnerRegistrationAuthorizationHash(
                    genesis_hash, payload);
            return dmn != nullptr && actual_authorization_hash &&
                   *actual_authorization_hash == expected_authorization_hash &&
                   llmq::pq::VerifyGlobalOwnerRegistrationAuthorization(
                       genesis_hash, payload, dmn->pdmnState->keyIDOwner);
        };
    return callbacks;
}
}

bool fMasternodeMode = false;

std::unique_ptr<CDeterministicMNManager> deterministicMNManager;

namespace {
using EvoEraseSet = std::unordered_set<uint256, StaticSaltedHasher>;

int64_t ElapsedMillis(const std::chrono::steady_clock::time_point& start)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start)
        .count();
}

void CollectRetainedSnapshotHashes(
    const CBlockIndex* tip,
    std::vector<uint256>& ordered_hashes,
    EvoEraseSet& retained_hashes)
{
    const auto& consensus = Params().GetConsensus();
    for (const CBlockIndex* pindex = tip;
         pindex != nullptr &&
         pindex->nHeight >= consensus.DIP0003Height &&
         ordered_hashes.size() < CDeterministicMNManager::LIST_CACHE_SIZE;
         pindex = pindex->pprev) {
        const uint256 block_hash = pindex->GetBlockHash();
        ordered_hashes.emplace_back(block_hash);
        retained_hashes.insert(block_hash);
    }

    // SYSCOIN: A genesis-active deployment has one exact base snapshot that
    // cannot be reproduced by ConnectBlock. Keep this single record outside
    // the bounded hot window; ordinary historical snapshots remain subject to
    // pruning.
    if (consensus.DIP0003Height == 0) {
        retained_hashes.insert(consensus.hashGenesisBlock);
    }

    if (consensus.nPQLegacyAnchorHeight != std::numeric_limits<int>::max() &&
        tip != nullptr && tip->nHeight >= consensus.nPQLegacyAnchorHeight) {
        if (const CBlockIndex* anchor = tip->GetAncestor(consensus.nPQLegacyAnchorHeight)) {
            retained_hashes.insert(anchor->GetBlockHash());
        }
    }
}

bool CollectPersistedKeysOutsideWindow(
    CEvoDB<uint256, CDeterministicMNList, StaticSaltedHasher>& evo_db,
    const EvoEraseSet& retained_hashes,
    std::optional<int32_t> finality_retention_floor,
    std::vector<uint256>& prune_keys,
    size_t& persisted_snapshot_count)
{
    std::unique_ptr<CDBIterator> cursor(evo_db.NewIterator());
    if (!cursor) {
        LogPrint(BCLog::SYS, "CDeterministicMNManager::%s -- Failed to create EvoDB iterator\n", __func__);
        return false;
    }

    for (cursor->SeekToFirst(); cursor->Valid(); cursor->Next()) {
        uint256 key;
        if (!cursor->GetKey(key)) return false;

        ++persisted_snapshot_count;
        std::optional<int32_t> snapshot_height;
        if (finality_retention_floor) {
            CDeterministicMNList snapshot;
            if (!cursor->GetValue(snapshot) ||
                snapshot.IsNull() ||
                snapshot.GetBlockHash() != key ||
                snapshot.GetHeight() < Params().GetConsensus().DIP0003Height) {
                // SYSCOIN: A corrupt value must not evade a height-aware
                // finality floor or be silently erased as if it were merely
                // old. Stop maintenance and require explicit DB recovery.
                LogPrintf("CDeterministicMNManager::%s -- invalid persisted "
                          "snapshot %s under finality retention\n",
                          __func__, key.ToString());
                return false;
            }
            snapshot_height = snapshot.GetHeight();
        }
        if (retained_hashes.count(key) != 0) continue;
        if (snapshot_height &&
            *snapshot_height >= *finality_retention_floor) continue;
        prune_keys.emplace_back(key);
    }

    return true;
}

bool WarmReadCacheFromWindow(
    CEvoDB<uint256, CDeterministicMNList, StaticSaltedHasher>& evo_db,
    const std::vector<uint256>& ordered_hashes)
{
    CDeterministicMNList snapshot;
    const size_t warm_count = std::min<size_t>(
        ordered_hashes.size(), CDeterministicMNManager::HOT_LIST_CACHE_SIZE);
    for (size_t i = warm_count; i > 0; --i) {
        if (!evo_db.ReadCache(ordered_hashes[i - 1], snapshot)) {
            LogPrint(BCLog::SYS,
                     "CDeterministicMNManager::%s -- Failed to warm read cache for %s\n",
                     __func__,
                     ordered_hashes[i - 1].ToString());
            return false;
        }
    }

    return true;
}
} // namespace

CDeterministicMNManager::CDeterministicMNManager(const DBParams& db_params)
    : m_pq_registry_db_params(MakePQRegistryDBParams(db_params)),
      m_payment_probation(
          std::make_unique<llmq::pq::PQPaymentProbationManager>(db_params))
{
    m_evoDb = std::make_unique<CEvoDB<uint256, CDeterministicMNList, StaticSaltedHasher>>(db_params, LIST_CACHE_SIZE);
    // SYSCOIN: Persist and validate the sole canonical base for a
    // genesis-active deterministic-masternode deployment.
    const auto& consensus{Params().GetConsensus()};
    const int64_t persisted_entry_count{m_evoDb->CountPersistedEntries()};
    if (consensus.DIP0003Height == 0) {
        CDeterministicMNList genesis_snapshot;
        const bool has_genesis_snapshot{m_evoDb->ReadCache(
            consensus.hashGenesisBlock, genesis_snapshot)};
        if (has_genesis_snapshot) {
            if (genesis_snapshot.IsNull() ||
                genesis_snapshot.GetHeight() != 0 ||
                genesis_snapshot.GetBlockHash() != consensus.hashGenesisBlock ||
                genesis_snapshot.GetAllMNsCount() != 0 ||
                genesis_snapshot.GetTotalRegisteredCount() != 0) {
                throw std::runtime_error(
                    "Invalid deterministic masternode genesis snapshot");
            }
        } else {
            // Genesis bypasses ConnectBlock's special-transaction state
            // transition, so an activation at height zero needs this one exact
            // empty base. Every later snapshot must still come from ProcessBlock.
            const CDeterministicMNList empty_genesis{
                consensus.hashGenesisBlock, 0, 0};
            if (!m_evoDb->WriteThrough(consensus.hashGenesisBlock,
                                       empty_genesis, /*fSync=*/true)) {
                throw std::runtime_error(
                    "Failed to persist deterministic masternode genesis snapshot");
            }
        }

    }

    // SYSCOIN: A raw entry count cannot prove that the current rolling window
    // was completely maintained before shutdown. Enable disk-backed reads now,
    // but let this process's first successful maintenance establish the flag.
    if (persisted_entry_count > 0 || consensus.DIP0003Height == 0) {
        m_evoDb->SetReadCacheSize(HOT_LIST_CACHE_SIZE);
    }
}

bool CDeterministicMNManager::GetPaymentProbationState(
    const CBlockIndex* pindex,
    llmq::pq::PQPaymentProbationState& state) const
{
    const uint256 state_hash{
        pindex == nullptr || pindex->pqPaymentProbationStateHash.IsNull()
            ? m_payment_probation->EmptyStateHash()
            : pindex->pqPaymentProbationStateHash};
    return m_payment_probation->GetState(state_hash, state);
}

bool CDeterministicMNManager::CommitPaymentProbationState(
    const llmq::pq::PQPaymentProbationState& state,
    const uint256& expected_hash,
    bool fJustCheck)
{
    return m_payment_probation->CommitState(state, expected_hash,
                                            fJustCheck);
}

uint256 CDeterministicMNManager::EmptyPaymentProbationStateHash() const
{
    return m_payment_probation->EmptyStateHash();
}

bool CDeterministicMNManager::PrunePaymentProbationStatesThroughEpoch(
    uint32_t prune_through_epoch,
    std::span<const uint256> retained_state_hashes)
{
    return m_payment_probation->PruneStatesThroughEpoch(
        prune_through_epoch, retained_state_hashes);
}

bool CDeterministicMNManager::GetMNPayeeForBlock(
    const CBlockIndex* pindex,
    CDeterministicMNCPtr& payee)
{
    payee.reset();
    if (pindex == nullptr) return false;
    llmq::pq::PQPaymentProbationState payment_state;
    if (!GetPaymentProbationState(pindex, payment_state)) return false;
    const auto list{GetListForBlock(pindex)};
    payee = list.GetMNPayee(&payment_state);
    return true;
}

llmq::pq::PQRegistryManager* CDeterministicMNManager::GetOrCreatePQRegistry(
    std::string& error) const
{
    llmq::pq::PQRegistryConfig config;
    const auto deployment = llmq::pq::GetPQRegistryConfig(
        Params().GetConsensus(), config);
    if (deployment == llmq::pq::PQRegistryDeploymentResult::DISABLED) {
        error = "pq-registry-disabled";
        return nullptr;
    }
    if (deployment != llmq::pq::PQRegistryDeploymentResult::VALID) {
        error = "pq-registry-invalid-configuration";
        return nullptr;
    }

    m_pq_registry_init_requested.store(true, std::memory_order_release);
    try {
        std::call_once(m_pq_registry_init_once, [this, &config] {
            m_pq_registry = std::make_unique<llmq::pq::PQRegistryManager>(
                m_pq_registry_db_params,
                Params().GetConsensus().hashGenesisBlock, config);
        });
    } catch (const std::exception& e) {
        error = strprintf("pq-registry-open-failed: %s", e.what());
        return nullptr;
    }
    if (!m_pq_registry) {
        error = "pq-registry-open-failed";
        return nullptr;
    }
    if (m_pq_registry->GetConfig() != config) {
        error = "pq-registry-configuration-changed";
        return nullptr;
    }
    error.clear();
    return m_pq_registry.get();
}

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

uint256 CDeterministicMNList::GetPQLegacyStateHash(const uint256& genesis_hash) const
{
    std::vector<CDeterministicMNCPtr> ordered;
    ordered.reserve(mnMap.size());
    for (const auto& item : mnMap) ordered.emplace_back(item.second);
    std::sort(ordered.begin(), ordered.end(), [](const auto& lhs, const auto& rhs) {
        return lhs->proTxHash < rhs->proTxHash;
    });

    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{PQ_LEGACY_STATE_DOMAIN.data(), PQ_LEGACY_STATE_DOMAIN.size()}));
    writer << genesis_hash << blockHash << nHeight << nTotalRegisteredCount;
    writer << static_cast<uint32_t>(ordered.size());
    for (const auto& dmn : ordered) {
        // SYSCOIN: this byte layout is deliberately independent from the
        // mutable database serializers used by post-anchor PQ state.
        writer << dmn->proTxHash
               << static_cast<uint64_t>(dmn->GetInternalId())
               << dmn->collateralOutpoint
               << dmn->nOperatorReward;
        dmn->pdmnState->SerializePQLegacyAnchorV1(writer);
    }
    return writer.GetHash();
}

CDeterministicMNCPtr CDeterministicMNList::GetValidMN(const uint256& proTxHash) const
{
    auto dmn = GetMN(proTxHash);
    if (dmn && !IsMNValid(*dmn)) {
        return nullptr;
    }
    return dmn;
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

static int CompareByLastPaid_GetHeight(
    const CDeterministicMN& dmn,
    const llmq::pq::PQPaymentProbationState* payment_state = nullptr)
{
    int height = dmn.pdmnState->nLastPaidHeight;
    if (dmn.pdmnState->nPoSeRevivedHeight != -1 && dmn.pdmnState->nPoSeRevivedHeight > height) {
        height = dmn.pdmnState->nPoSeRevivedHeight;
    } else if (height == 0) {
        height = dmn.pdmnState->nRegisteredHeight;
    }
    if (payment_state != nullptr) {
        height = std::max(
            height,
            payment_state->PaymentEligibleSinceHeight(dmn.proTxHash));
    }
    return height;
}

static bool CompareByLastPaid(
    const CDeterministicMN& _a,
    const CDeterministicMN& _b,
    const llmq::pq::PQPaymentProbationState* payment_state = nullptr)
{
    int ah = CompareByLastPaid_GetHeight(_a, payment_state);
    int bh = CompareByLastPaid_GetHeight(_b, payment_state);
    if (ah == bh) {
        return _a.proTxHash < _b.proTxHash;
    } else {
        return ah < bh;
    }
}
static bool CompareByLastPaid(const CDeterministicMN* _a,
                              const CDeterministicMN* _b)
{
    return CompareByLastPaid(*_a, *_b);
}

CDeterministicMNCPtr CDeterministicMNList::GetMNPayee(
    const llmq::pq::PQPaymentProbationState* payment_state) const
{
    if (mnMap.size() == 0) {
        return nullptr;
    }

    CDeterministicMNCPtr best;
    CDeterministicMNCPtr ordinary_best;
    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        if (!ordinary_best ||
            CompareByLastPaid(dmn.get(), ordinary_best.get())) {
            ordinary_best = dmn;
        }
        if (payment_state != nullptr &&
            payment_state->IsPaymentWithheld(dmn->proTxHash)) {
            return;
        }
        if (!best || CompareByLastPaid(*dmn, *best, payment_state)) {
            best = dmn;
        }
    });

    // Consensus must retain a payee even if every eligible MN is withheld.
    // This fail-open fallback prevents an audit result from burning rewards or
    // halting mining while still removing isolated free riders from rotation.
    return best ? best : ordinary_best;
}

std::vector<CDeterministicMNCPtr>
CDeterministicMNList::GetProjectedMNPayees(
    int nCount,
    const llmq::pq::PQPaymentProbationState* payment_state) const
{
    if (nCount < 0 ) {
        return {};
    }

    std::vector<CDeterministicMNCPtr> result;
    std::vector<CDeterministicMNCPtr> ordinary_fallback;
    result.reserve(GetValidMNsCount());
    ordinary_fallback.reserve(GetValidMNsCount());

    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        ordinary_fallback.emplace_back(dmn);
        if (payment_state == nullptr ||
            !payment_state->IsPaymentWithheld(dmn->proTxHash)) {
            result.emplace_back(dmn);
        }
    });

    const bool all_withheld{result.empty() && !ordinary_fallback.empty()};
    if (all_withheld) result = ordinary_fallback;
    std::sort(result.begin(), result.end(), [&](const auto& a, const auto& b) {
        return CompareByLastPaid(*a, *b,
                                 all_withheld ? nullptr : payment_state);
    });

    result.resize(std::min<std::size_t>(
        result.size(), static_cast<std::size_t>(nCount)));

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
    static const int TESTNET_MIN_REGISTRATION_HEIGHT = 1000000;
    int nAllowedLegacyNodes = 25;
    int nLegacyNodeCount = 0;
    std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>> scores;
    scores.reserve(GetAllMNsCount());
    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        if (dmn->pdmnState->confirmedHash.IsNull()) {
            // we only take confirmed MNs into account to avoid hash grinding on the ProRegTxHash to sneak MNs into a
            // future quorums
            return;
        }
        // remove old defunct nodes on testnet
         if(fTestNet && dmn->pdmnState->nRegisteredHeight < TESTNET_MIN_REGISTRATION_HEIGHT) {
            nLegacyNodeCount++;
            if(nLegacyNodeCount > nAllowedLegacyNodes) {
                // Assign the lowest possible score (0) to deprioritize with descending sort
                LogPrint(BCLog::MNLIST, "CDeterministicMNList::%s -- Assigning score 0 to testnet MN %s (registered height %d < %d) due to limit %d\n",
                        __func__, dmn->proTxHash.ToString(), dmn->pdmnState->nRegisteredHeight, TESTNET_MIN_REGISTRATION_HEIGHT, nAllowedLegacyNodes);
                scores.emplace_back(arith_uint256(0), dmn);
                return; // Skip normal calculation
            }
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
    for (const auto& p : to.mnMap) {
        const auto& toPtr = p.second;
        auto fromPtr = GetMN(toPtr->proTxHash);
        if (fromPtr == nullptr) {
            // Masternode is newly added.
            if (!toPtr->pdmnState->vchNEVMAddress.empty()) {
                NEVMDiffEntry entry;
                entry.type = NEVMDiffType::Added;
                entry.newAddress = toPtr->pdmnState->vchNEVMAddress;
                entry.collateralHeight = uint32_t(toPtr->pdmnState->nCollateralHeight);
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
                        entry.collateralHeight = uint32_t(toPtr->pdmnState->nCollateralHeight);
                    } else {
                        // Address was updated.
                        entry.type = NEVMDiffType::Updated;
                        entry.oldAddress = fromPtr->pdmnState->vchNEVMAddress;
                        entry.newAddress = toPtr->pdmnState->vchNEVMAddress;
                        entry.collateralHeight = uint32_t(toPtr->pdmnState->nCollateralHeight);
                    }
                    nevmDiffMap[toPtr->proTxHash] = entry;
                }
                diffRet.updatedMNs.emplace(toPtr->GetInternalId(), std::move(stateDiff));
            }
        }
    };
    if (mnMap.size() + diffRet.addedMNs.size() != to.mnMap.size()) {
        // Process removals from the old list.
        for (auto& fromPtr : mnMap) {
            const auto toPtr = to.GetMN(fromPtr.second->proTxHash);
            if (toPtr == nullptr) {
                // Masternode removed entirely.
                if (!fromPtr.second->pdmnState->vchNEVMAddress.empty()) {
                    NEVMDiffEntry entry;
                    entry.type = NEVMDiffType::Removed;
                    entry.oldAddress = fromPtr.second->pdmnState->vchNEVMAddress;
                    nevmDiffMap[fromPtr.second->proTxHash] = entry;
                }
                diffRet.removedMns.emplace(fromPtr.second->GetInternalId());
                if (mnMap.size() + diffRet.addedMNs.size() - diffRet.removedMns.size() == to.mnMap.size()) break;
            } else if (toPtr->pdmnState->vchNEVMAddress.empty() && !fromPtr.second->pdmnState->vchNEVMAddress.empty()) {
                // Masternode still exists but its NEVM address was cleared.
                NEVMDiffEntry entry;
                entry.type = NEVMDiffType::Removed;
                entry.oldAddress = fromPtr.second->pdmnState->vchNEVMAddress;
                nevmDiffMap[fromPtr.second->proTxHash] = entry;
            }
        };
    }

    // Convert the deduplicated map into a deterministic order before filling diff vectors.
    std::vector<std::pair<uint256, NEVMDiffEntry>> orderedNEVMDiffEntries;
    orderedNEVMDiffEntries.reserve(nevmDiffMap.size());
    for (const auto& pair : nevmDiffMap) {
        orderedNEVMDiffEntries.emplace_back(pair.first, pair.second);
    }
    std::sort(orderedNEVMDiffEntries.begin(), orderedNEVMDiffEntries.end(),
              [](const auto& a, const auto& b) {
                  return a.first < b.first;
              });

    for (const auto& pair : orderedNEVMDiffEntries) {
        const NEVMDiffEntry& entry = pair.second;
        switch (entry.type) {
            case NEVMDiffType::Added:
                diffRetNEVMAddress.addedMNNEVM.emplace_back(entry.newAddress, entry.collateralHeight);
                break;
            case NEVMDiffType::Updated:
                diffRetNEVMAddress.updatedMNNEVM.emplace_back(entry.oldAddress, std::make_pair(entry.newAddress, entry.collateralHeight));
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
    if (dmn->pdmnState->pubKeyOperator.IsValid() && !AddUniqueProperty(*dmn, dmn->pdmnState->pubKeyOperator)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate pubKeyOperator=%s", __func__,
                dmn->proTxHash.ToString(), dmn->pdmnState->pubKeyOperator.ToString())));
    }
    if (!dmn->pdmnState->vchNEVMAddress.empty() && !AddUniqueProperty(*dmn, dmn->pdmnState->vchNEVMAddress)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't add a masternode %s with a duplicate vchNEVMAddress=%s", __func__,
                dmn->proTxHash.ToString(), dmn->pdmnState->pubKeyOperator.ToString())));
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
                oldDmn.proTxHash.ToString(), pdmnState->pubKeyOperator.ToString())));
    }
    if (!UpdateUniqueProperty(*dmn, oldState->vchNEVMAddress, pdmnState->vchNEVMAddress)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't update a masternode %s with a duplicate old vchNEVMAddress=%s vs new vchNEVMAddress=%s", __func__,
                oldDmn.proTxHash.ToString(), HexStr(oldState->vchNEVMAddress), HexStr(pdmnState->vchNEVMAddress))));
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
    if (dmn->pdmnState->pubKeyOperator.IsValid() && !DeleteUniqueProperty(*dmn, dmn->pdmnState->pubKeyOperator)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a pubKeyOperator=%s", __func__,
                proTxHash.ToString(), dmn->pdmnState->pubKeyOperator.ToString())));
    }
    if (!dmn->pdmnState->vchNEVMAddress.empty() && !DeleteUniqueProperty(*dmn, dmn->pdmnState->vchNEVMAddress)) {
        mnUniquePropertyMap = mnUniquePropertyMapSaved;
        throw(std::runtime_error(strprintf("%s: Can't delete a masternode %s with a vchNEVMAddress=%s", __func__,
                proTxHash.ToString(), HexStr(dmn->pdmnState->vchNEVMAddress))));
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
        updatedStr += strprintf("(OldAddress=%s, NewAddress=%s, CollateralHeight=%d) ", HexStr(entry.first), HexStr(entry.second.first), entry.second.second);
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

bool CDeterministicMNManager::ProcessBlock(const CBlock& block, const CBlockIndex* pindex, BlockValidationState& _state, const CCoinsViewCache& view, const llmq::CFinalCommitmentTxPayload& legacy_commitment, CDeterministicMNListNEVMAddressDiff &diffNEVM, bool fJustCheck, bool ibd)
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

        if (!BuildNewListFromBlock(block, pindex->pprev, _state, view, newList,
                                   oldList, legacy_commitment)) {
            // pass the state returned by the function above
            return false;
        }

        newList.SetBlockHash(pindex->GetBlockHash());

        uint256 pq_registry_state_root;
        llmq::pq::PQRegistryConfig pq_config;
        const auto pq_deployment = llmq::pq::GetPQRegistryConfig(
            consensusParams, pq_config);
        if (pq_deployment ==
            llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-pq-registry-configuration");
        }
        if (pq_deployment == llmq::pq::PQRegistryDeploymentResult::VALID) {
            std::string registry_open_error;
            auto* registry = GetOrCreatePQRegistry(registry_open_error);
            if (registry == nullptr) {
                LogPrintf("%s -- %s\n", __func__, registry_open_error);
                return _state.Error("failed-pq-registry-open");
            }
            const auto callbacks = MakePQRegistryCallbacks(
                oldList, newList, consensusParams.hashGenesisBlock);
            llmq::pq::PQRegistryError registry_error;
            if (!registry->ProcessBlock(block, nHeight, callbacks, fJustCheck,
                                        registry_error,
                                        &pq_registry_state_root)) {
                LogPrintf("%s -- PQ registry rejected height=%d tx=%u protx=%s result=%s state_result=%u\n",
                          __func__, nHeight,
                          static_cast<unsigned>(registry_error.transaction_index),
                          registry_error.pro_tx_hash.ToString(),
                          std::string{llmq::pq::PQRegistryResultString(
                              registry_error.result)},
                          static_cast<unsigned>(registry_error.state_result));
                return _state.Invalid(
                    BlockValidationResult::BLOCK_CONSENSUS,
                    strprintf("bad-pq-%s",
                              std::string{llmq::pq::PQRegistryResultString(
                                  registry_error.result)}));
            }
        } else {
            for (const auto& transaction : block.vtx) {
                if (transaction &&
                    transaction->nVersion ==
                        llmq::pq::PQ_GLOBAL_KEY_TX_VERSION) {
                    return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                          "bad-pq-registry-disabled");
                }
            }
            const auto empty_root = EmptyPQRegistryStateRoot(
                consensusParams.hashGenesisBlock);
            if (!empty_root) {
                return _state.Error("failed-pq-empty-registry-root");
            }
            pq_registry_state_root = *empty_root;
        }

        if (!Consensus::CheckPQLegacyState(
                consensusParams, nHeight,
                newList.GetPQLegacyStateHash(consensusParams.hashGenesisBlock),
                pq_registry_state_root)) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-pq-legacy-state");
        }

        if (fJustCheck) {
            return true;
        }

        if(!ibd || (fNEVMConnection && fNexusActive && newList.m_changed_nevm_address)) {
            oldList.BuildDiff(newList, diff, diffNEVM);
        }
        if(!ibd) {
            if (diff.HasChanges()) {
                GetMainSignals().NotifyMasternodeListChanged(false, oldList, diff);
            }
            // always update interface for payment detail changes
            uiInterface.NotifyMasternodeListChanged(newList);
        }
        bool replay_write_through{false};
        int finality_retention_floor{std::numeric_limits<int>::max()};
        {
            LOCK(cs);
            replay_write_through =
                m_replay_snapshot_retention_floor !=
                    std::numeric_limits<int>::max() ||
                m_finality_snapshot_publication_pending;
            finality_retention_floor = m_finality_snapshot_retention_floor;
        }
        const bool finality_roster_write_through{
            !replay_write_through &&
            finality_retention_floor != std::numeric_limits<int>::max() &&
            nHeight >= finality_retention_floor &&
            pq_deployment == llmq::pq::PQRegistryDeploymentResult::VALID &&
            consensusParams.nPQRosterSnapshotLag > 0 &&
            llmq::pq::IsRegistrationCutoffHeight(
                pq_config.schedule,
                static_cast<uint32_t>(consensusParams.nPQRosterSnapshotLag),
                nHeight)};
        if (nHeight == consensusParams.nPQLegacyAnchorHeight ||
            replay_write_through || finality_roster_write_through) {
            // SYSCOIN: IBD deliberately postpones normal EvoDB maintenance. The
            // migration snapshot must reach disk before the bounded dirty FIFO
            // can evict it as replay advances beyond the cache window. A live
            // BTCC/NEVM replay marker extends the same write-ahead requirement
            // to every later snapshot, including an arbitrarily long NULL-
            // receipt tail whose marker never otherwise mutates. Without a
            // marker, only exact roster cutoffs are written through on every
            // branch; persisting every historical full list would make IBD
            // disk use grow with chain history while maintenance is deferred.
            if (!m_evoDb->WriteThrough(pindex->GetBlockHash(), newList, /*fSync=*/true)) {
                if (replay_write_through) {
                    return _state.Error("failed-btcc-replay-dmn-persist");
                }
                return _state.Error(finality_roster_write_through
                    ? "failed-finality-roster-dmn-persist"
                    : "failed-pq-anchor-dmn-persist");
            }
        } else {
            m_evoDb->WriteCache(pindex->GetBlockHash(), std::move(newList));
        }
       
    // SYSCOIN: EvoDB failures are local availability errors, not evidence
    // that every peer must reject this otherwise-valid block as consensus bad.
    } catch (const dbwrapper_error& e) {
        LogPrintf("CDeterministicMNManager::%s -- database error: %s\n",
                  __func__, e.what());
        return _state.Error("failed-dmn-persist");
    } catch (const std::exception& e) {
        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- internal error: %s\n", __func__, e.what());
        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "failed-dmn-block");
    }

    return true;
}


bool CDeterministicMNManager::UndoBlock(const CBlockIndex* pindex, CDeterministicMNListNEVMAddressDiff &inversedDiffNEVMAddress)
{
    if (pindex == nullptr) return false;
    llmq::pq::PQRegistryConfig pq_config;
    const auto pq_deployment = llmq::pq::GetPQRegistryConfig(
        Params().GetConsensus(), pq_config);
    if (pq_deployment ==
        llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
        return false;
    }
    if (pq_deployment == llmq::pq::PQRegistryDeploymentResult::VALID &&
        pindex->nHeight >= pq_config.preparation_height) {
        std::string registry_open_error;
        auto* registry = GetOrCreatePQRegistry(registry_open_error);
        if (registry == nullptr) return false;
        llmq::pq::PQRegistrySnapshot parent_snapshot;
        llmq::pq::PQRegistryError registry_error;
        if (!registry->UndoBlock(pindex->GetBlockHash(), pindex->nHeight,
                                 parent_snapshot, registry_error)) {
            LogPrintf("%s -- PQ registry undo failed at height=%d block=%s result=%s\n",
                      __func__, pindex->nHeight,
                      pindex->GetBlockHash().ToString(),
                      std::string{llmq::pq::PQRegistryResultString(
                          registry_error.result)});
            return false;
        }
    }

    uint256 blockHash = pindex->GetBlockHash();

    CDeterministicMNList curList;
    CDeterministicMNList prevList;
    bool readCache = m_evoDb->ReadCache(blockHash, curList);
    if(readCache) {
        prevList = GetListForBlockInternal(pindex->pprev);
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

bool CDeterministicMNManager::BuildNewListFromBlock(const CBlock& block, const CBlockIndex* pindexPrev, BlockValidationState& _state, const CCoinsViewCache& view, CDeterministicMNList& mnListRet, CDeterministicMNList& oldList, const llmq::CFinalCommitmentTxPayload& legacy_commitment)
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
    llmq::pq::PQPaymentProbationState payment_state;
    if (!GetPaymentProbationState(pindexPrev, payment_state)) {
        return _state.Error("failed-pq-payment-probation-state");
    }
    auto payee = oldList.GetMNPayee(&payment_state);
    // at least 2 rounds of payments before registered MN's gets put in list
    const size_t mnCountThreshold = oldList.GetValidMNsCount()*2;
    // we iterate the oldList here and update the newList
    // this is only valid as long these have not diverged at this point, which is the case as long as we don't add
    // code above this loop that modifies newList
    std::vector<CDeterministicMNCPtr> toDecrease;
    toDecrease.reserve(oldList.GetAllMNsCount() / 10);
    oldList.ForEachMNShared(false, [&decreasePoSE, &oldList, &toDecrease, &mnCountThreshold, &pindexPrev, &newList](const CDeterministicMNCPtr& dmn) {
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

    if (!legacy_commitment.IsNull()) {
        const auto& consensus{Params().GetConsensus()};
        const auto anchor_result{
            Consensus::CheckPQLegacyAnchorConfiguration(consensus)};
        if (anchor_result != Consensus::PQLegacyAnchorResult::VALID ||
            nHeight > consensus.nPQLegacyAnchorHeight) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-retired");
        }
        if (legacy_commitment.nHeight != static_cast<uint32_t>(nHeight)) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-cbtx-height");
        }

        const auto& replay{consensus.legacyQuorumReplay};
        if (replay.size <= 0 ||
            replay.size > static_cast<int>(llmq::legacy::MAX_QUORUM_MEMBERS) ||
            replay.threshold <= 0 || replay.threshold > replay.size ||
            replay.session_interval <= 0) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-replay-params");
        }
        const int quorum_height{
            nHeight - (nHeight % replay.session_interval)};
        const CBlockIndex* quorum_base{
            pindexPrev != nullptr ? pindexPrev->GetAncestor(quorum_height)
                                  : nullptr};
        if (quorum_base == nullptr ||
            quorum_base->GetBlockHash() !=
                legacy_commitment.commitment.quorumHash) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-quorum-hash");
        }

        const auto quorum_list{GetListForBlock(quorum_base)};
        const auto members{quorum_list.CalculateQuorum(
            static_cast<std::size_t>(replay.size),
            quorum_base->GetBlockHash())};
        if (std::any_of(members.begin(), members.end(),
                        [](const CDeterministicMNCPtr& member) {
                            return member == nullptr;
                        })) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-structure");
        }
        const auto& commitment{legacy_commitment.commitment};
        if (!commitment.IsStructurallyValid(
                static_cast<std::size_t>(replay.size), members.size(),
                static_cast<std::size_t>(replay.threshold),
                llmq::CFinalCommitment::GetVersion(
                    quorum_base->nHeight >= consensus.nV19StartBlock))) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-qc-structure");
        }

        // SYSCOIN: this is historical state reconstruction, not live DKG.
        // Missing participation changed PoSe bans and subsequent payee state,
        // which an anchor hash alone cannot recreate without a snapshot.
        if (!commitment.IsNull()) {
            for (std::size_t i{0}; i < members.size(); ++i) {
                if (!newList.HasMN(members[i]->proTxHash)) {
                    continue;
                }
                if (!commitment.validMembers[i]) {
                    newList.PoSePunish(members[i]->proTxHash,
                                       newList.CalcPenalty(66));
                }
            }
        }
    }

    // SYSCOIN: A PQ revocation is the terminal provider mutation for its block. Without
    // this rule, a later service update could repopulate fields that an earlier
    // revocation cleared, making the resulting DMN state order-dependent.
    std::unordered_map<uint256, std::size_t, StaticSaltedHasher>
        provider_mutation_counts;
    std::unordered_set<uint256, StaticSaltedHasher> pq_revocations;
    for (const auto& transaction : block.vtx) {
        if (!transaction) continue;
        const auto mutation = DecodeProviderMutationIdentity(*transaction);
        if (!mutation) continue;
        ++provider_mutation_counts[mutation->pro_tx_hash];
        if (mutation->is_pq_revocation) {
            pq_revocations.emplace(mutation->pro_tx_hash);
        }
    }
    for (const auto& pro_tx_hash : pq_revocations) {
        const auto count = provider_mutation_counts.find(pro_tx_hash);
        if (count == provider_mutation_counts.end() || count->second != 1) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-protx-pq-revoke-conflict");
        }
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
                if (newList.HasUniqueProperty(proTx.keyIDOwner) ||
                    (proTx.nVersion <= CProRegTx::BASIC_BLS_VERSION &&
                     newList.HasUniqueProperty(proTx.pubKeyOperator))) {
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

                if (proTx.addr == CService() || proTx.nVersion == CProRegTx::PQ_VERSION) {
                    // SYSCOIN: A PQ registration has no operator key until a later tx86
                    // is committed against this DMN's parent snapshot.
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
                    bool has_active_operator_key{false};
                    if (proTx.nVersion <= CProUpServTx::UPDATE_NEVM_VERSION) {
                        has_active_operator_key = newState->pubKeyOperator.IsValid();
                    } else {
                        llmq::pq::PQRegistrySnapshot parent_snapshot;
                        std::string registry_error;
                        if (!GetPQRegistrySnapshot(pindexPrev, parent_snapshot, registry_error)) {
                            LogPrintf("%s -- failed to load parent PQ registry for %s: %s\n",
                                      __func__, proTx.proTxHash.ToString(), registry_error);
                            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                                  "bad-protx-pq-registry-state");
                        }
                        const auto* operator_state = parent_snapshot.FindOperator(proTx.proTxHash);
                        has_active_operator_key = operator_state != nullptr &&
                                                  operator_state->HasActiveGlobalKey() &&
                                                  pq_revocations.count(proTx.proTxHash) == 0;
                    }
                    if (has_active_operator_key && !newState->keyIDVoting.IsNull() && !newState->keyIDOwner.IsNull()) {
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
            
                // SYSCOIN: Opaque BLS bytes are historical state after the PQ fork. A
                // PQ registrar update changes only owner-controlled metadata.
                if (proTx.nVersion <= CProUpRegTx::BASIC_BLS_VERSION &&
                    newState->pubKeyOperator != proTx.pubKeyOperator) {
                    if(!newState->vchNEVMAddress.empty()) {
                        newList.m_changed_nevm_address = true;
                    }
                    newState->ResetOperatorFields();
                    newState->BanIfNotBanned(nHeight);
                    newState->nVersion = proTx.nVersion;
                    newState->pubKeyOperator = proTx.pubKeyOperator;
                }
                if (proTx.nVersion == CProUpRegTx::PQ_VERSION) {
                    newState->nVersion = proTx.nVersion;
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
                if(!newState->vchNEVMAddress.empty()) {
                    newList.m_changed_nevm_address = true;
                }
                newState->ResetOperatorFields();
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
    if (auto dmn = payee ? newList.GetMN(payee->proTxHash) : nullptr) {
        auto newState = std::make_shared<CDeterministicMNState>(*dmn->pdmnState);
        newState->nLastPaidHeight = nHeight;
        newList.UpdateMN(payee->proTxHash, newState);
    }

    mnListRet = std::move(newList);
    return true;
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
    if (!m_evoDb->ReadCache(pindex->GetBlockHash(), snapshot)) {
        throw std::runtime_error(strprintf(
            "%s: missing deterministic masternode snapshot at height=%d block=%s",
            __func__, pindex->nHeight, pindex->GetBlockHash().ToString()));
    }
    if (snapshot.IsNull() || snapshot.GetHeight() != pindex->nHeight ||
        snapshot.GetBlockHash() != pindex->GetBlockHash()) {
        throw std::runtime_error(strprintf(
            "%s: invalid deterministic masternode snapshot at height=%d block=%s",
            __func__, pindex->nHeight, pindex->GetBlockHash().ToString()));
    }
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

bool CDeterministicMNManager::CheckPQTransaction(
    const CTransaction& tx,
    const CBlockIndex* pindexPrev,
    TxValidationState& state,
    bool fJustCheck,
    bool check_sigs)
{
    if (tx.nVersion != llmq::pq::PQ_GLOBAL_KEY_TX_VERSION) {
        return FormatSyscoinErrorMessage(state, "bad-pq-tx-version",
                                         fJustCheck);
    }
    if (pindexPrev == nullptr) {
        return FormatSyscoinErrorMessage(state, "bad-pq-missing-parent",
                                         fJustCheck);
    }

    std::string registry_error;
    auto* registry = GetOrCreatePQRegistry(registry_error);
    if (registry == nullptr) {
        return FormatSyscoinErrorMessage(state, registry_error, fJustCheck);
    }

    CDeterministicMNList parent_list;
    try {
        parent_list = GetListForBlockInternal(pindexPrev);
    } catch (const std::exception&) {
        return FormatSyscoinErrorMessage(state, "bad-pq-missing-dmn-parent",
                                         fJustCheck);
    }
    const auto callbacks = MakePQRegistryCallbacks(
        parent_list, parent_list, Params().GetConsensus().hashGenesisBlock);
    llmq::pq::PQRegistryError error;
    if (!registry->ValidateTransaction(tx, pindexPrev->GetBlockHash(),
                                       pindexPrev->nHeight + 1, callbacks,
                                       check_sigs, error)) {
        return FormatSyscoinErrorMessage(
            state,
            strprintf("bad-pq-%s",
                      std::string{llmq::pq::PQRegistryResultString(
                          error.result)}),
            fJustCheck);
    }
    return true;
}

bool CDeterministicMNManager::GetPQRegistrySnapshot(
    const CBlockIndex* pindex,
    llmq::pq::PQRegistrySnapshot& snapshot,
    std::string& error) const
{
    if (pindex == nullptr) {
        error = "pq-registry-null-block-index";
        return false;
    }
    auto* registry = GetOrCreatePQRegistry(error);
    if (registry == nullptr) return false;

    llmq::pq::PQRegistryError registry_error;
    const uint256 previous_hash =
        pindex->pprev == nullptr ? uint256{} : pindex->pprev->GetBlockHash();
    if (!registry->GetSnapshot(pindex->GetBlockHash(), previous_hash,
                               pindex->nHeight, snapshot, registry_error)) {
        error = strprintf("%s at height=%d block=%s",
                          std::string{llmq::pq::PQRegistryResultString(
                              registry_error.result)},
                          pindex->nHeight,
                          pindex->GetBlockHash().ToString());
        return false;
    }
    error.clear();
    return true;
}

bool CDeterministicMNManager::GetPQRegistryMempoolView(
    const CBlockIndex* pindex,
    std::span<const uint256> requested_operators,
    llmq::pq::PQRegistryMempoolView& view,
    std::string& error) const
{
    if (pindex == nullptr) {
        error = "pq-registry-null-block-index";
        return false;
    }
    auto* registry = GetOrCreatePQRegistry(error);
    if (registry == nullptr) return false;

    llmq::pq::PQRegistryError registry_error;
    if (!registry->GetMempoolView(
            pindex->GetBlockHash(), pindex->nHeight, requested_operators,
            view, registry_error)) {
        error = strprintf(
            "pq-registry-mempool-view-%s",
            std::string{llmq::pq::PQRegistryResultString(
                registry_error.result)});
        return false;
    }
    return true;
}

bool CDeterministicMNManager::VerifyPQLegacyAnchorState(const CBlockIndex* anchor)
{
    if (anchor == nullptr ||
        anchor->nHeight != Params().GetConsensus().nPQLegacyAnchorHeight ||
        anchor->GetBlockHash() != Params().GetConsensus().hashPQLegacyAnchorBlock) {
        return false;
    }

    CDeterministicMNList snapshot;
    if (!m_evoDb->ReadCache(anchor->GetBlockHash(), snapshot)) return false;
    uint256 pq_state_root;
    llmq::pq::PQRegistryConfig config;
    const auto deployment = llmq::pq::GetPQRegistryConfig(
        Params().GetConsensus(), config);
    if (deployment ==
        llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
        return false;
    }
    if (deployment == llmq::pq::PQRegistryDeploymentResult::VALID) {
        llmq::pq::PQRegistrySnapshot pq_snapshot;
        std::string error;
        if (!GetPQRegistrySnapshot(anchor, pq_snapshot, error)) return false;
        pq_state_root = pq_snapshot.consensus_state_root;
    } else {
        const auto empty_root = EmptyPQRegistryStateRoot(
            Params().GetConsensus().hashGenesisBlock);
        if (!empty_root) return false;
        pq_state_root = *empty_root;
    }
    return !snapshot.IsNull() &&
           snapshot.GetHeight() == anchor->nHeight &&
           snapshot.GetBlockHash() == anchor->GetBlockHash() &&
           Consensus::CheckPQLegacyState(
               Params().GetConsensus(), anchor->nHeight,
               snapshot.GetPQLegacyStateHash(
                   Params().GetConsensus().hashGenesisBlock),
               pq_state_root);
}

bool CDeterministicMNManager::VerifyPersistedPQRegistrySnapshot(
    const CBlockIndex* pindex)
{
    if (pindex == nullptr) return false;
    llmq::pq::PQRegistryConfig config;
    const auto deployment = llmq::pq::GetPQRegistryConfig(
        Params().GetConsensus(), config);
    if (deployment == llmq::pq::PQRegistryDeploymentResult::DISABLED) {
        return true;
    }
    if (deployment != llmq::pq::PQRegistryDeploymentResult::VALID) {
        return false;
    }
    if (pindex->nHeight < config.preparation_height) return true;

    llmq::pq::PQRegistrySnapshot snapshot;
    std::string error;
    if (!GetPQRegistrySnapshot(pindex, snapshot, error)) {
        LogPrintf("%s -- %s\n", __func__, error);
        return false;
    }
    return snapshot.height == pindex->nHeight &&
           snapshot.block_hash == pindex->GetBlockHash() &&
           snapshot.IsStructurallyValid();
}

bool CDeterministicMNManager::VerifyPersistedSnapshot(const CBlockIndex* pindex)
{
    if (pindex == nullptr) return false;
    if (pindex->nHeight < Params().GetConsensus().DIP0003Height) return true;

    CDeterministicMNList snapshot;
    if (!m_evoDb->Read(pindex->GetBlockHash(), snapshot)) return false;
    return !snapshot.IsNull() &&
           snapshot.GetHeight() == pindex->nHeight &&
           snapshot.GetBlockHash() == pindex->GetBlockHash();
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

bool CDeterministicMNManager::DoMaintenance(bool bForceFlush, bool fSync) {
    if (!bForceFlush) {
        return true;
    }

    llmq::pq::PQRegistryManager* pq_registry{nullptr};
    if (m_pq_registry_init_requested.load(std::memory_order_acquire)) {
        std::string registry_error;
        pq_registry = GetOrCreatePQRegistry(registry_error);
        if (pq_registry == nullptr) {
            LogPrintf("%s -- PQ registry unavailable during maintenance: %s\n",
                      __func__, registry_error);
            return false;
        }
    }
    if (pq_registry != nullptr && !pq_registry->Flush(fSync)) {
        return false;
    }

    LOCK(m_evoDb->cs);
    const auto maintenance_start = std::chrono::steady_clock::now();
    const CBlockIndex* tip{nullptr};
    int replay_retention_floor{std::numeric_limits<int>::max()};
    int finality_retention_floor{std::numeric_limits<int>::max()};
    bool retain_all_finality_snapshots{false};
    uint64_t replay_retention_generation{0};
    {
        LOCK(cs);
        tip = tipIndex;
        replay_retention_floor = m_replay_snapshot_retention_floor;
        finality_retention_floor = m_finality_snapshot_retention_floor;
        retain_all_finality_snapshots =
            m_finality_snapshot_verifications_in_flight != 0 ||
            m_finality_snapshot_publication_pending;
        replay_retention_generation =
            m_replay_snapshot_retention_generation;
    }
    if (tip == nullptr) {
        const size_t cache_entry_count{m_evoDb->GetReadWriteCacheSize()};
        const size_t erase_entry_count{m_evoDb->GetEraseCacheSize()};
        if (cache_entry_count == 0 && erase_entry_count == 0) {
            return true;
        }
        LogPrint(BCLog::SYS,
                 "CDeterministicMNManager::%s maintenance without tip; flushing dirty=%zu erase=%zu only elapsed=%d ms\n",
                 __func__,
                 cache_entry_count,
                 erase_entry_count,
                 ElapsedMillis(maintenance_start));
        return m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync);
    }

    const uint256 tip_hash = tip->GetBlockHash();
    const size_t cache_entry_count{m_evoDb->GetReadWriteCacheSize()};
    const size_t erase_entry_count{m_evoDb->GetEraseCacheSize()};
    const bool persistent_window_initialized =
        m_persistent_window_initialized.load(std::memory_order_relaxed);

    if (cache_entry_count == 0 && erase_entry_count == 0 &&
        WITH_LOCK(cs, return m_last_maintained_tip == tip_hash)) {
        LogPrint(BCLog::SYS,
                 "CDeterministicMNManager::%s no-op; tip=%s already maintained elapsed=%d ms\n",
                 __func__,
                 tip_hash.ToString(),
                 ElapsedMillis(maintenance_start));
        return true;
    }

    std::vector<uint256> retained_hashes_ordered;
    retained_hashes_ordered.reserve(LIST_CACHE_SIZE);
    EvoEraseSet retained_hashes;
    retained_hashes.reserve(LIST_CACHE_SIZE * 2);
    CollectRetainedSnapshotHashes(tip, retained_hashes_ordered, retained_hashes);

    LogPrint(BCLog::SYS,
             "CDeterministicMNManager::%s maintenance start tip=%s height=%d dirty=%zu erase=%zu retained=%zu persistent_window_initialized=%d\n",
             __func__,
             tip_hash.ToString(),
             tip->nHeight,
             cache_entry_count,
             erase_entry_count,
             retained_hashes_ordered.size(),
             persistent_window_initialized);

    if ((cache_entry_count != 0 || erase_entry_count != 0) &&
        !m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) {
        return false;
    }

    std::vector<uint256> prune_keys;
    size_t persisted_snapshot_count{0};
    const bool retain_replay_snapshots{
        replay_retention_floor != std::numeric_limits<int>::max()};
    if (retain_replay_snapshots || retain_all_finality_snapshots) {
        // SYSCOIN: A replay marker can protect both active and prospective
        // branches. Skipping disk pruning while it exists preserves every
        // fork-local DMN snapshot without warming the bounded read cache. An
        // in-flight verification or durable side-branch winner uses the same
        // fail-closed policy until publication is either abandoned or fully
        // enforced. Outage disk growth is intentionally unbounded.
        const int64_t count{m_evoDb->CountPersistedEntries()};
        if (count < 0) return false;
        persisted_snapshot_count = static_cast<size_t>(count);
    } else if (!CollectPersistedKeysOutsideWindow(
                   *m_evoDb, retained_hashes,
                   finality_retention_floor == std::numeric_limits<int>::max()
                       ? std::nullopt
                       : std::optional<int32_t>{finality_retention_floor},
                   prune_keys,
                   persisted_snapshot_count)) {
        return false;
    }

    for (const uint256& key : prune_keys) {
        m_evoDb->EraseCache(key);
        if (pq_registry != nullptr &&
            !pq_registry->PruneSnapshot(key, /*fSync=*/false)) {
            return false;
        }
    }
    if (!prune_keys.empty() && pq_registry != nullptr &&
        !pq_registry->Flush(fSync)) {
        return false;
    }
    if (!prune_keys.empty() && !m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) {
        return false;
    }

    const bool should_initialize_hot_cache =
        !persistent_window_initialized && !retained_hashes_ordered.empty();
    if (should_initialize_hot_cache) {
        m_evoDb->SetReadCacheSize(HOT_LIST_CACHE_SIZE);
        if (!WarmReadCacheFromWindow(*m_evoDb, retained_hashes_ordered)) {
            return false;
        }
        m_persistent_window_initialized.store(true, std::memory_order_relaxed);
    }

    {
        LOCK(cs);
        if (m_replay_snapshot_retention_generation ==
            replay_retention_generation) {
            m_last_maintained_tip = tip_hash;
        } else {
            m_last_maintained_tip.SetNull();
        }
    }
    LogPrint(BCLog::SYS,
             "CDeterministicMNManager::%s maintenance complete tip=%s persisted=%zu pruned=%zu replay_retention_floor=%d finality_retention_floor=%d retain_all_finality=%d read_cache=%zu initialized_hot_cache=%d elapsed=%d ms\n",
             __func__,
             tip_hash.ToString(),
             persisted_snapshot_count,
             prune_keys.size(),
             replay_retention_floor,
             finality_retention_floor,
             retain_all_finality_snapshots,
             m_evoDb->GetReadCacheSize(),
             should_initialize_hot_cache,
             ElapsedMillis(maintenance_start));
    return true;
}
bool CDeterministicMNManager::FlushCacheToDisk(bool bForceFlush, bool fSync) {
    return DoMaintenance(bForceFlush, fSync);
}

bool CDeterministicMNManager::FlushPendingSnapshotsToDisk(bool fSync)
{
    if (!m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) return false;
    if (!m_payment_probation->Flush(fSync)) return false;
    if (!m_pq_registry_init_requested.load(std::memory_order_acquire)) {
        return true;
    }
    std::string registry_error;
    auto* pq_registry = GetOrCreatePQRegistry(registry_error);
    if (pq_registry == nullptr) {
        LogPrintf("%s -- PQ registry unavailable while flushing: %s\n",
                  __func__, registry_error);
        return false;
    }
    return pq_registry->Flush(fSync);
}

int CDeterministicMNManager::UpdateReplaySnapshotRetentionFloor(
    std::optional<int32_t> floor)
{
    LOCK(cs);
    const int disabled{std::numeric_limits<int>::max()};
    const int requested{
        floor ? std::max<int>(*floor, Params().GetConsensus().DIP0003Height)
              : disabled};
    const int next{
        floor ? std::min(m_replay_snapshot_retention_floor, requested)
              : disabled};
    if (next != m_replay_snapshot_retention_floor) {
        m_replay_snapshot_retention_floor = next;
        ++m_replay_snapshot_retention_generation;
        // SYSCOIN: Clearing the crash-restored replay obligation must force
        // same-tip maintenance to revisit and compact the retained disk set.
        m_last_maintained_tip.SetNull();
    }
    return m_replay_snapshot_retention_floor;
}

int CDeterministicMNManager::UpdateFinalitySnapshotRetentionFloor(
    std::optional<int32_t> floor)
{
    LOCK(cs);
    const int next{
        floor ? std::max<int>(*floor, Params().GetConsensus().DIP0003Height)
              : std::numeric_limits<int>::max()};
    if (next != m_finality_snapshot_retention_floor) {
        m_finality_snapshot_retention_floor = next;
        ++m_replay_snapshot_retention_generation;
        // SYSCOIN: Durable best/unsealed replacement can make a same-tip
        // database either newly protected or newly eligible for compaction.
        m_last_maintained_tip.SetNull();
    }
    return m_finality_snapshot_retention_floor;
}

void CDeterministicMNManager::BeginFinalitySnapshotVerificationRetention()
{
    // SYSCOIN: Match DoMaintenance's EvoDB->manager lock order. When this
    // returns, an already-running pruning pass has completed and no later pass
    // can sample an unprotected state before the candidate reads its rosters.
    LOCK(m_evoDb->cs);
    LOCK(cs);
    ++m_finality_snapshot_verifications_in_flight;
    ++m_replay_snapshot_retention_generation;
    m_last_maintained_tip.SetNull();
}

void CDeterministicMNManager::EndFinalitySnapshotVerificationRetention()
{
    LOCK(m_evoDb->cs);
    LOCK(cs);
    assert(m_finality_snapshot_verifications_in_flight != 0);
    --m_finality_snapshot_verifications_in_flight;
    ++m_replay_snapshot_retention_generation;
    m_last_maintained_tip.SetNull();
}

void CDeterministicMNManager::UpdateFinalitySnapshotPublicationRetention(
    bool retain)
{
    LOCK(m_evoDb->cs);
    LOCK(cs);
    if (m_finality_snapshot_publication_pending == retain) return;
    m_finality_snapshot_publication_pending = retain;
    ++m_replay_snapshot_retention_generation;
    // SYSCOIN: Both arming and releasing must defeat the same-tip maintenance
    // shortcut. Arming follows any already-running prune; releasing permits
    // accumulated fork snapshots to be compacted immediately.
    m_last_maintained_tip.SetNull();
}
bool CDeterministicMNManager::HasPersistentWindow() const
{
    return m_persistent_window_initialized.load(std::memory_order_relaxed);
}
bool CDeterministicMNManager::GetEvoDBStats(EvoDBStats& stats)
{
    if (!m_evoDb) {
        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- EvoDB not initialized.\n", __func__);
        stats = {}; // Clear stats
        return false;
    }

    try {
        // Get DB path from parameters used to initialize CEvoDB
        stats.dbPath = fs::PathToString(m_evoDb->GetDBParams().path);
        stats.cacheEntries = m_evoDb->GetReadWriteCacheSize();
        stats.eraseCacheEntries = m_evoDb->GetEraseCacheSize();
        stats.approxPersistedEntries = m_evoDb->CountPersistedEntries(); 

        // Calculate disk size by iterating directory
        stats.estimatedDiskSizeBytes = 0; // Initialize size
        if (!stats.dbPath.empty() && fs::is_directory(stats.dbPath)) {
            try { // Add inner try-catch for filesystem iteration errors
                for (const auto& dir_entry : fs::recursive_directory_iterator(stats.dbPath)) {
                    if (fs::is_regular_file(dir_entry.path())) {
                        std::error_code ec;
                        uint64_t fileSize = fs::file_size(dir_entry.path(), ec);
                        if (ec) {
                            LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- Error getting file size for %s: %s\n", __func__, fs::PathToString(dir_entry.path()), ec.message());
                            // Optionally continue or return false depending on desired strictness
                        } else {
                            stats.estimatedDiskSizeBytes += fileSize;
                        }
                    }
                }
            } catch (const fs::filesystem_error& e) {
                 LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- Filesystem error while iterating %s: %s\n", __func__, stats.dbPath, e.what());
                 // Can't reliably estimate size, maybe return false or keep size 0
                 return false; // Indicate failure if iteration fails
            }
        } else if (!stats.dbPath.empty()) {
            LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- DB path '%s' is not a valid directory.\n", __func__, stats.dbPath);
             // Path specified but not a directory, size is effectively 0, but maybe log warning.
        } else {
            LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- DB path is empty.\n", __func__);
        }

        return true;

    } catch (const std::exception& e) {
        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- Exception: %s\n", __func__, e.what());
        stats = {}; // Clear stats on error
        return false;
    } catch (...) {
        LogPrint(BCLog::MNLIST, "CDeterministicMNManager::%s -- Unknown exception.\n", __func__);
        stats = {}; // Clear stats on error
        return false;
    }
}
