// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/deterministicmns.h>
#include <evo/specialtx.h>

#include <base58.h>
#include <chainparams.h>
#include <core_io.h>
#include <consensus/pq_migration.h>
#include <hash.h>
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
#include <stdexcept>

namespace {
constexpr std::string_view PQ_LEGACY_STATE_DOMAIN{"SYS_PQ_LEGACY_DMN_STATE_V1"};
constexpr std::string_view DMN_INVERSE_BASE_DOMAIN{
    "SYS_DMN_INVERSE_BASE_V1"};
constexpr std::string_view DMN_INVERSE_HISTORY_DOMAIN{
    "SYS_DMN_INVERSE_HISTORY_V1"};

uint256 GetDMNInverseBaseCommitment(
    const uint256& genesis_hash,
    int32_t base_height,
    const uint256& base_hash,
    const uint256& base_state_hash)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{DMN_INVERSE_BASE_DOMAIN.data(),
                              DMN_INVERSE_BASE_DOMAIN.size()}));
    writer << genesis_hash << base_height << base_hash << base_state_hash;
    return writer.GetHash();
}

uint256 GetDMNInverseHistoryCommitment(
    const CDeterministicMNListInverse& inverse)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{DMN_INVERSE_HISTORY_DOMAIN.data(),
                              DMN_INVERSE_HISTORY_DOMAIN.size()}));
    writer << inverse.version << inverse.genesis_hash
           << inverse.coverage_base_height
           << inverse.parent_history_commitment << inverse.child_height
           << inverse.child_hash << inverse.child_state_hash
           << inverse.parent_height << inverse.parent_hash
           << inverse.parent_state_hash
           << inverse.parent_total_registered_count
           << ::SerializeHash(inverse.inverse_diff);
    return writer.GetHash();
}

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

DBParams MakeDMNInverseJournalDBParams(DBParams params)
{
    if (params.path.empty()) {
        params.path = "evodb_dmn_inverse";
    } else {
        params.path = params.path.parent_path() /
            (fs::PathToString(params.path.filename()) + "_inverse");
    }
    params.cache_bytes = std::max<std::size_t>(1, params.cache_bytes / 8);
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
                     "CDeterministicMNManager::%s -- Failed to warm read cache entry for %s\n",
                     __func__,
                     ordered_hashes[i - 1].ToString());
            return false;
        }
    }

    return true;
}

bool ReconstructParentFromInverse(
    const CDeterministicMNListInverse& inverse,
    const CBlockIndex* child,
    const CDeterministicMNList& child_list,
    CDeterministicMNList& parent_list,
    std::string& error)
{
    if (child == nullptr || child->pprev == nullptr ||
        !inverse.IsStructurallyValid() ||
        inverse.genesis_hash != Params().GetConsensus().hashGenesisBlock ||
        inverse.coverage_base_height !=
            Params().GetConsensus().DIP0003Height ||
        inverse.child_height != child->nHeight ||
        inverse.child_hash != child->GetBlockHash() ||
        inverse.parent_height != child->pprev->nHeight ||
        inverse.parent_hash != child->pprev->GetBlockHash() ||
        child_list.IsNull() || child_list.GetHeight() != child->nHeight ||
        child_list.GetBlockHash() != child->GetBlockHash()) {
        error = "inverse journal metadata mismatch";
        return false;
    }

    const uint256& genesis_hash{inverse.genesis_hash};
    if (child_list.GetOrComputePQLegacyStateHash(genesis_hash) !=
        inverse.child_state_hash) {
        error = "inverse journal child integrity mismatch";
        return false;
    }

    try {
        parent_list = child_list.ApplyDiff(
            child->pprev, inverse.inverse_diff,
            inverse.parent_total_registered_count);
    } catch (const std::exception& exception) {
        error = strprintf("inverse journal application failed: %s",
                          exception.what());
        return false;
    }
    if (parent_list.IsNull() ||
        parent_list.GetHeight() != child->pprev->nHeight ||
        parent_list.GetBlockHash() != child->pprev->GetBlockHash() ||
        parent_list.GetTotalRegisteredCount() !=
            inverse.parent_total_registered_count ||
        parent_list.GetOrComputePQLegacyStateHash(genesis_hash) !=
            inverse.parent_state_hash) {
        error = "inverse journal parent integrity mismatch";
        return false;
    }
    error.clear();
    return true;
}
} // namespace

bool CDeterministicMNListInverse::IsStructurallyValid() const
{
    if (version != VERSION || genesis_hash.IsNull() ||
        coverage_base_height < 0 ||
        coverage_base_height > parent_height ||
        parent_history_commitment.IsNull() || history_commitment.IsNull() ||
        history_commitment != GetDMNInverseHistoryCommitment(*this) ||
        child_height <= 0 ||
        parent_height != child_height - 1 || child_hash.IsNull() ||
        parent_hash.IsNull() || child_hash == parent_hash ||
        child_state_hash.IsNull() || parent_state_hash.IsNull() ||
        inverse_diff.addedMNs.size() > MAX_CHANGES ||
        inverse_diff.updatedMNs.size() > MAX_CHANGES ||
        inverse_diff.removedMns.size() > MAX_CHANGES ||
        inverse_diff.addedMNs.size() + inverse_diff.updatedMNs.size() >
            MAX_CHANGES ||
        inverse_diff.addedMNs.size() + inverse_diff.updatedMNs.size() +
                inverse_diff.removedMns.size() >
            MAX_CHANGES) {
        return false;
    }

    std::unordered_set<uint64_t> changed_ids;
    changed_ids.reserve(inverse_diff.addedMNs.size() +
                        inverse_diff.updatedMNs.size() +
                        inverse_diff.removedMns.size());
    std::unordered_set<uint256, StaticSaltedHasher> added_hashes;
    added_hashes.reserve(inverse_diff.addedMNs.size());
    for (const auto& dmn : inverse_diff.addedMNs) {
        if (dmn == nullptr || dmn->pdmnState == nullptr ||
            dmn->proTxHash.IsNull() ||
            dmn->GetInternalId() >= parent_total_registered_count ||
            !changed_ids.emplace(dmn->GetInternalId()).second ||
            !added_hashes.emplace(dmn->proTxHash).second) {
            return false;
        }
    }
    // The inverse journal intentionally freezes the state-diff field language
    // through vchNEVMAddress. A later field is rejected until a new journal
    // schema defines how it participates in parent-state reconstruction.
    static constexpr uint32_t INVERSE_STATE_DIFF_FIELDS{
        (static_cast<uint32_t>(
             CDeterministicMNStateDiff::Field_vchNEVMAddress)
         << 1) -
        1};
    for (const auto& [internal_id, state_diff] : inverse_diff.updatedMNs) {
        if (internal_id >= parent_total_registered_count ||
            state_diff.fields == 0 ||
            (state_diff.fields & ~INVERSE_STATE_DIFF_FIELDS) != 0 ||
            !changed_ids.emplace(internal_id).second) {
            return false;
        }
    }
    for (const uint64_t internal_id : inverse_diff.removedMns) {
        if (!changed_ids.emplace(internal_id).second) return false;
    }
    return true;
}

CDeterministicMNManager::CDeterministicMNManager(const DBParams& db_params)
    : m_pq_registry_db_params(MakePQRegistryDBParams(db_params)),
      m_payment_probation(
          std::make_unique<llmq::pq::PQPaymentProbationManager>(db_params)),
      m_inverse_journal(std::make_unique<CEvoDB<
          uint256, CDeterministicMNListInverse, StaticSaltedHasher>>(
          MakeDMNInverseJournalDBParams(db_params), /*maxCacheSizeIn=*/0,
          /*maxReadCacheSizeIn=*/2))
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

bool CDeterministicMNManager::CommitInverseJournal(
    const CBlockIndex* child,
    const CDeterministicMNList& child_list,
    CDeterministicMNList& parent_list,
    const uint256& child_state_hash)
{
    if (child == nullptr || child->pprev == nullptr || child_list.IsNull() ||
        parent_list.IsNull() || child_state_hash.IsNull()) {
        return false;
    }

    try {
        const auto& consensus{Params().GetConsensus()};
        if (child->pprev->nHeight < consensus.DIP0003Height) return false;
        CDeterministicMNListInverse inverse;
        inverse.genesis_hash = consensus.hashGenesisBlock;
        inverse.coverage_base_height = consensus.DIP0003Height;
        inverse.child_height = child->nHeight;
        inverse.child_hash = child->GetBlockHash();
        inverse.child_state_hash = child_state_hash;
        inverse.parent_height = child->pprev->nHeight;
        inverse.parent_hash = child->pprev->GetBlockHash();
        inverse.parent_total_registered_count =
            parent_list.GetTotalRegisteredCount();
        child_list.BuildTrackedInverseDiff(parent_list, inverse.inverse_diff);
        const uint256 parent_state_hash{
            parent_list.GetOrComputePQLegacyStateHash(
                consensus.hashGenesisBlock)};

        if (child->pprev->nHeight == consensus.DIP0003Height) {
            inverse.parent_state_hash = parent_state_hash;
            inverse.parent_history_commitment = GetDMNInverseBaseCommitment(
                consensus.hashGenesisBlock, child->pprev->nHeight,
                child->pprev->GetBlockHash(), inverse.parent_state_hash);
        } else {
            CDeterministicMNListInverse parent_inverse;
            if (!m_inverse_journal->ReadCache(child->pprev->GetBlockHash(),
                                              parent_inverse) ||
                !parent_inverse.IsStructurallyValid() ||
                parent_inverse.genesis_hash != consensus.hashGenesisBlock ||
                parent_inverse.coverage_base_height !=
                    consensus.DIP0003Height ||
                parent_inverse.child_height != child->pprev->nHeight ||
                parent_inverse.child_hash != child->pprev->GetBlockHash() ||
                parent_inverse.child_state_hash != parent_state_hash) {
                LogPrintf("%s -- incomplete deterministic-MN inverse history "
                          "before height=%d block=%s; reindex is required\n",
                          __func__, child->nHeight,
                          child->GetBlockHash().ToString());
                return false;
            }
            inverse.parent_state_hash = parent_inverse.child_state_hash;
            inverse.parent_history_commitment =
                parent_inverse.history_commitment;
        }
        inverse.history_commitment =
            GetDMNInverseHistoryCommitment(inverse);

        CDeterministicMNListInverse existing;
        if (m_inverse_journal->ReadCache(child->GetBlockHash(), existing)) {
            if (!existing.IsStructurallyValid() ||
                ::SerializeHash(existing) != ::SerializeHash(inverse)) {
                LogPrintf("%s -- conflicting deterministic-MN inverse for "
                          "height=%d block=%s\n",
                          __func__, child->nHeight,
                          child->GetBlockHash().ToString());
                return false;
            }
            return true;
        }
        if (m_inverse_journal->ExistsCache(child->GetBlockHash())) {
            LogPrintf("%s -- unreadable deterministic-MN inverse for "
                      "height=%d block=%s\n",
                      __func__, child->nHeight,
                      child->GetBlockHash().ToString());
            return false;
        }

        if (!inverse.IsStructurallyValid() ||
            !m_inverse_journal->WriteThrough(
                child->GetBlockHash(), inverse, /*fSync=*/false)) {
            LogPrintf("%s -- failed to publish deterministic-MN inverse for "
                      "height=%d block=%s\n",
                      __func__, child->nHeight,
                      child->GetBlockHash().ToString());
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        LogPrintf("%s -- deterministic-MN inverse database failure at "
                  "height=%d block=%s: %s\n",
                  __func__, child->nHeight,
                  child->GetBlockHash().ToString(), exception.what());
        return false;
    }
}

bool CDeterministicMNManager::LoadAndVerifyInverseJournal(
    const CBlockIndex* child,
    const CDeterministicMNList& child_list,
    CDeterministicMNList& parent_list)
{
    if (child == nullptr || child->pprev == nullptr) return false;

    try {
        CDeterministicMNListInverse inverse;
        if (!m_inverse_journal->ReadCache(child->GetBlockHash(), inverse)) {
            LogPrintf("%s -- missing deterministic-MN inverse coverage at "
                      "height=%d block=%s; reindex is required\n",
                      __func__, child->nHeight,
                      child->GetBlockHash().ToString());
            return false;
        }
        const auto& consensus{Params().GetConsensus()};
        if (inverse.parent_height == consensus.DIP0003Height) {
            if (inverse.parent_history_commitment !=
                GetDMNInverseBaseCommitment(
                    consensus.hashGenesisBlock, inverse.parent_height,
                    inverse.parent_hash, inverse.parent_state_hash)) {
                LogPrintf("%s -- corrupt deterministic-MN inverse base seal "
                          "at height=%d block=%s; reindex is required\n",
                          __func__, child->nHeight,
                          child->GetBlockHash().ToString());
                return false;
            }
        } else {
            CDeterministicMNListInverse parent_inverse;
            if (!m_inverse_journal->ReadCache(inverse.parent_hash,
                                              parent_inverse) ||
                !parent_inverse.IsStructurallyValid() ||
                parent_inverse.genesis_hash != inverse.genesis_hash ||
                parent_inverse.coverage_base_height !=
                    inverse.coverage_base_height ||
                parent_inverse.child_height != inverse.parent_height ||
                parent_inverse.child_hash != inverse.parent_hash ||
                parent_inverse.child_state_hash !=
                    inverse.parent_state_hash ||
                parent_inverse.history_commitment !=
                    inverse.parent_history_commitment) {
                LogPrintf("%s -- missing or corrupt deterministic-MN parent "
                          "inverse before height=%d block=%s; reindex is "
                          "required\n",
                          __func__, child->nHeight,
                          child->GetBlockHash().ToString());
                return false;
            }
        }
        std::string error;
        if (!ReconstructParentFromInverse(inverse, child, child_list,
                                          parent_list, error)) {
            LogPrintf("%s -- corrupt deterministic-MN inverse at height=%d "
                      "block=%s: %s; reindex is required\n",
                      __func__, child->nHeight,
                      child->GetBlockHash().ToString(), error);
            return false;
        }

        return true;
    } catch (const std::exception& exception) {
        LogPrintf("%s -- deterministic-MN inverse recovery failure at "
                  "height=%d block=%s: %s; reindex is required\n",
                  __func__, child != nullptr ? child->nHeight : -1,
                  child != nullptr ? child->GetBlockHash().ToString()
                                   : uint256{}.ToString(),
                  exception.what());
        return false;
    }
}

bool CDeterministicMNManager::EnsureRetainedSnapshotWindow(
    const CBlockIndex* tip,
    const CDeterministicMNList& tip_list)
{
    const auto& consensus{Params().GetConsensus()};
    if (tip == nullptr || tip->nHeight < consensus.DIP0003Height ||
        tip_list.IsNull() || tip_list.GetHeight() != tip->nHeight ||
        tip_list.GetBlockHash() != tip->GetBlockHash()) {
        return false;
    }

    const int oldest_height{std::max(
        consensus.DIP0003Height,
        tip->nHeight - LIST_CACHE_SIZE + 1)};
    const CBlockIndex* oldest{tip->GetAncestor(oldest_height)};
    if (oldest == nullptr) return false;
    CDeterministicMNList oldest_snapshot;
    if (m_evoDb->ReadCache(oldest->GetBlockHash(), oldest_snapshot)) {
        return !oldest_snapshot.IsNull() &&
               oldest_snapshot.GetHeight() == oldest->nHeight &&
               oldest_snapshot.GetBlockHash() == oldest->GetBlockHash();
    }
    if (m_evoDb->ExistsCache(oldest->GetBlockHash())) {
        LogPrintf("%s -- unreadable oldest retained deterministic-MN "
                  "snapshot at height=%d block=%s\n",
                  __func__, oldest->nHeight,
                  oldest->GetBlockHash().ToString());
        return false;
    }

    std::vector<const CBlockIndex*> path;
    path.reserve(static_cast<size_t>(tip->nHeight - oldest_height + 1));
    for (const CBlockIndex* cursor{tip};
         cursor != nullptr && cursor->nHeight >= oldest_height;
         cursor = cursor->pprev) {
        path.emplace_back(cursor);
    }
    if (path.empty() || path.back()->nHeight != oldest_height) {
        LogPrintf("%s -- incomplete active-chain index while restoring the "
                  "deterministic-MN snapshot window at tip=%s height=%d\n",
                  __func__, tip->GetBlockHash().ToString(), tip->nHeight);
        return false;
    }
    std::reverse(path.begin(), path.end());

    const auto valid_snapshot = [](const CDeterministicMNList& snapshot,
                                   const CBlockIndex* index) {
        return index != nullptr && !snapshot.IsNull() &&
               snapshot.GetHeight() == index->nHeight &&
               snapshot.GetBlockHash() == index->GetBlockHash();
    };

    CDeterministicMNList child_list;
    size_t child_position{path.size()};
    for (size_t position{0}; position < path.size(); ++position) {
        CDeterministicMNList candidate;
        if (m_evoDb->ReadCache(path[position]->GetBlockHash(), candidate)) {
            if (!valid_snapshot(candidate, path[position])) {
                LogPrintf("%s -- invalid retained deterministic-MN snapshot "
                          "at height=%d block=%s\n",
                          __func__, path[position]->nHeight,
                          path[position]->GetBlockHash().ToString());
                return false;
            }
            child_list = std::move(candidate);
            child_position = position;
            break;
        }
        if (m_evoDb->ExistsCache(path[position]->GetBlockHash())) {
            LogPrintf("%s -- unreadable retained deterministic-MN snapshot "
                      "at height=%d block=%s\n",
                      __func__, path[position]->nHeight,
                      path[position]->GetBlockHash().ToString());
            return false;
        }
    }

    if (child_position == path.size()) {
        child_list = tip_list;
        child_position = path.size() - 1;
    }

    for (size_t position{child_position}; position > 0; --position) {
        CDeterministicMNList expected_parent;
        if (!LoadAndVerifyInverseJournal(path[position], child_list,
                                         expected_parent)) {
            return false;
        }

        CDeterministicMNList persisted_parent;
        if (m_evoDb->ReadCache(path[position - 1]->GetBlockHash(),
                               persisted_parent)) {
            if (!valid_snapshot(persisted_parent, path[position - 1]) ||
                persisted_parent.GetOrComputePQLegacyStateHash(
                    consensus.hashGenesisBlock) !=
                    expected_parent.GetOrComputePQLegacyStateHash(
                        consensus.hashGenesisBlock)) {
                LogPrintf("%s -- retained deterministic-MN snapshot "
                          "conflicts with inverse history at height=%d "
                          "block=%s\n",
                          __func__, path[position - 1]->nHeight,
                          path[position - 1]->GetBlockHash().ToString());
                return false;
            }
            child_list = std::move(persisted_parent);
            continue;
        }
        if (m_evoDb->ExistsCache(path[position - 1]->GetBlockHash()) ||
            !m_evoDb->WriteThrough(path[position - 1]->GetBlockHash(),
                                   expected_parent, /*fSync=*/false)) {
            LogPrintf("%s -- failed to restore retained deterministic-MN "
                      "snapshot at height=%d block=%s\n",
                      __func__, path[position - 1]->nHeight,
                      path[position - 1]->GetBlockHash().ToString());
            return false;
        }
        child_list = std::move(expected_parent);
    }
    return true;
}

bool CDeterministicMNManager::EnsureRetainedSnapshotWindow(
    const CBlockIndex* tip)
{
    if (tip == nullptr) return false;
    if (tip->nHeight < Params().GetConsensus().DIP0003Height) return true;
    CDeterministicMNList tip_list;
    if (!m_evoDb->ReadCache(tip->GetBlockHash(), tip_list)) return false;
    return EnsureRetainedSnapshotWindow(tip, tip_list);
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

bool CDeterministicMNManager::IsPaymentProbationGCCompleteForCheckpoint(
    const llmq::pq::PaymentAuditStoreCheckpoint& checkpoint) const
{
    return m_payment_probation->IsGCCompleteForCheckpoint(checkpoint);
}

bool CDeterministicMNManager::PrunePaymentProbationStatesThroughCheckpoint(
    const llmq::pq::PaymentAuditStoreCheckpoint& checkpoint,
    std::span<const uint256> retained_state_hashes)
{
    return m_payment_probation->PruneStatesThroughCheckpoint(
        checkpoint, retained_state_hashes);
}

bool CDeterministicMNManager::GetMNPayeeForBlock(
    const CBlockIndex* pindex,
    CDeterministicMNCPtr& payee)
{
    payee.reset();
    if (pindex == nullptr) return false;
    llmq::pq::PQPaymentProbationState payment_state;
    if (!GetPaymentProbationState(pindex, payment_state)) return false;
    llmq::pq::PQPaymentEligibleProTxHashesPtr pq_payment_eligible;
    if (!GetPQPaymentEligibleProTxHashes(pindex, pq_payment_eligible)) {
        return false;
    }
    const auto list{GetListForBlock(pindex)};
    payee = list.GetMNPayee(
        &payment_state,
        pq_payment_eligible.get());
    return true;
}

bool CDeterministicMNManager::GetProjectedMNPayeesForBlock(
    const CBlockIndex* pindex,
    int count,
    std::vector<CDeterministicMNCPtr>& payees)
{
    // SYSCOIN: A projection owns the same branch-local eligibility inputs as
    // exact consensus selection and cannot cross into an unknown frozen set.
    payees.clear();
    if (pindex == nullptr || count < 0 ||
        pindex->nHeight == std::numeric_limits<int>::max()) {
        return false;
    }
    if (count == 0) return true;

    const auto& consensus{Params().GetConsensus()};
    const int first_payment_height{pindex->nHeight + 1};
    const auto eligibility{
        Consensus::CheckPQPaymentEligibility(consensus,
                                             first_payment_height)};
    int known_count{count};
    if (eligibility == Consensus::PQPaymentEligibilityResult::LEGACY) {
        if (Consensus::CheckPQChainLockAnchorConfiguration(consensus) ==
            Consensus::PQAnchorResult::VALID) {
            const int64_t available{
                static_cast<int64_t>(consensus.nPQChainLockAnchorHeight) -
                first_payment_height + 1};
            if (available <= 0) return false;
            known_count = static_cast<int>(std::min<int64_t>(
                known_count, available));
        }
    } else if (eligibility ==
               Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED) {
        llmq::pq::PQRegistryConfig config;
        if (llmq::pq::GetPQRegistryConfig(consensus, config) !=
            llmq::pq::PQRegistryDeploymentResult::VALID) {
            return false;
        }
        const auto epoch{llmq::pq::EpochForHeight(
            config.schedule, first_payment_height)};
        const auto epoch_end{epoch ? llmq::pq::EpochEndHeightExclusive(
                                         config.schedule, *epoch)
                                   : std::nullopt};
        if (!epoch_end || *epoch_end <= first_payment_height) return false;
        known_count = std::min(known_count,
                               *epoch_end - first_payment_height);
    } else {
        return false;
    }

    llmq::pq::PQPaymentProbationState payment_state;
    if (!GetPaymentProbationState(pindex, payment_state)) return false;
    llmq::pq::PQPaymentEligibleProTxHashesPtr pq_payment_eligible;
    if (!GetPQPaymentEligibleProTxHashes(pindex, pq_payment_eligible)) {
        return false;
    }
    const auto list{GetListForBlock(pindex)};
    payees = list.GetProjectedMNPayees(
        known_count, &payment_state,
        pq_payment_eligible.get());
    return true;
}

bool CDeterministicMNManager::GetPQPaymentEligibleProTxHashes(
    const CBlockIndex* pindex,
    llmq::pq::PQPaymentEligibleProTxHashesPtr& eligible) const
{
    eligible.reset();
    if (pindex == nullptr ||
        pindex->nHeight == std::numeric_limits<int>::max()) {
        return false;
    }
    const auto& consensus{Params().GetConsensus()};
    const int payment_height{pindex->nHeight + 1};
    const auto eligibility{
        Consensus::CheckPQPaymentEligibility(consensus, payment_height)};
    if (eligibility == Consensus::PQPaymentEligibilityResult::LEGACY) {
        return true;
    }
    if (eligibility !=
        Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED) {
        return false;
    }

    llmq::pq::PQRegistryConfig config;
    if (llmq::pq::GetPQRegistryConfig(consensus, config) !=
        llmq::pq::PQRegistryDeploymentResult::VALID) {
        return false;
    }
    const auto epoch{
        llmq::pq::EpochForHeight(config.schedule, payment_height)};
    if (!epoch) return false;

    // SYSCOIN: Payment selection is a per-block hot path. Reuse the immutable
    // branch/root/epoch-derived view instead of copying, re-hashing, and
    // rescanning the complete PQ registry for every caller.
    std::string open_error;
    auto* registry{GetOrCreatePQRegistry(open_error)};
    if (registry == nullptr) {
        LogPrintf("%s -- %s\n", __func__, open_error);
        return false;
    }
    llmq::pq::PQRegistryError registry_error;
    const uint256 previous_hash{
        pindex->pprev == nullptr ? uint256{}
                                 : pindex->pprev->GetBlockHash()};
    if (!registry->GetPaymentEligibleProTxHashes(
            pindex->GetBlockHash(), previous_hash, pindex->nHeight, *epoch,
            eligible, registry_error)) {
        LogPrintf("%s -- %s at height=%d block=%s\n", __func__,
                  std::string{llmq::pq::PQRegistryResultString(
                      registry_error.result)},
                  pindex->nHeight, pindex->GetBlockHash().ToString());
        return false;
    }
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

uint256 CDeterministicMNList::GetOrComputePQLegacyStateHash(
    const uint256& genesis_hash) const
{
    if (!m_pq_legacy_state_hash ||
        m_pq_legacy_state_hash_genesis != genesis_hash) {
        m_pq_legacy_state_hash = GetPQLegacyStateHash(genesis_hash);
        m_pq_legacy_state_hash_genesis = genesis_hash;
    }
    return *m_pq_legacy_state_hash;
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
    const llmq::pq::PQPaymentProbationState* payment_state,
    const llmq::pq::PQPaymentEligibleProTxHashes* pq_payment_eligible) const
{
    if (mnMap.size() == 0) {
        return nullptr;
    }

    CDeterministicMNCPtr best;
    CDeterministicMNCPtr ordinary_best;
    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        // SYSCOIN: Root capability is an admission gate, not another queue-age
        // penalty. A restored operator keeps its accrued age and one payment
        // moves it to the back through the ordinary nLastPaidHeight update.
        if (pq_payment_eligible != nullptr &&
            !std::binary_search(pq_payment_eligible->begin(),
                                pq_payment_eligible->end(),
                                dmn->proTxHash)) {
            return;
        }
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
    const llmq::pq::PQPaymentProbationState* payment_state,
    const llmq::pq::PQPaymentEligibleProTxHashes* pq_payment_eligible) const
{
    if (nCount < 0 ) {
        return {};
    }

    std::vector<CDeterministicMNCPtr> result;
    std::vector<CDeterministicMNCPtr> ordinary_fallback;
    result.reserve(GetValidMNsCount());
    ordinary_fallback.reserve(GetValidMNsCount());

    ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
        // SYSCOIN: The fail-open withheld fallback remains inside the same
        // frozen-root admission set as the ordinary projected queue.
        if (pq_payment_eligible != nullptr &&
            !std::binary_search(pq_payment_eligible->begin(),
                                pq_payment_eligible->end(),
                                dmn->proTxHash)) {
            return;
        }
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

void CDeterministicMNList::BuildTrackedInverseDiff(
    const CDeterministicMNList& parent,
    CDeterministicMNListDiff& inverse) const
{
    inverse = {};
    for (const uint256& pro_tx_hash : m_tracked_changes) {
        const auto child_dmn{GetMN(pro_tx_hash)};
        const auto parent_dmn{parent.GetMN(pro_tx_hash)};
        if (child_dmn == nullptr && parent_dmn == nullptr) continue;
        if (child_dmn == nullptr) {
            inverse.addedMNs.emplace_back(parent_dmn);
            continue;
        }
        if (parent_dmn == nullptr) {
            inverse.removedMns.emplace(child_dmn->GetInternalId());
            continue;
        }
        if (child_dmn->GetInternalId() != parent_dmn->GetInternalId() ||
            child_dmn->collateralOutpoint != parent_dmn->collateralOutpoint ||
            child_dmn->nOperatorReward != parent_dmn->nOperatorReward) {
            throw std::runtime_error(
                "unsupported in-place deterministic masternode identity change");
        }
        CDeterministicMNStateDiff state_diff{
            *child_dmn->pdmnState, *parent_dmn->pdmnState};
        if (state_diff.fields != 0) {
            inverse.updatedMNs.emplace(child_dmn->GetInternalId(),
                                       std::move(state_diff));
        }
    }
    std::sort(inverse.addedMNs.begin(), inverse.addedMNs.end(),
              [](const CDeterministicMNCPtr& lhs,
                 const CDeterministicMNCPtr& rhs) {
                  return lhs->GetInternalId() < rhs->GetInternalId();
              });
}

std::vector<uint256>
CDeterministicMNList::BuildTrackedNetRemovedProTxHashes(
    const CDeterministicMNList& parent) const
{
    std::vector<uint256> removed;
    for (const uint256& pro_tx_hash : m_tracked_changes) {
        if (parent.HasMN(pro_tx_hash) && !HasMN(pro_tx_hash)) {
            removed.emplace_back(pro_tx_hash);
        }
    }
    return removed;
}

CDeterministicMNList CDeterministicMNList::ApplyDiff(
    const CBlockIndex* pindex,
    const CDeterministicMNListDiff& diff,
    std::optional<uint32_t> total_registered_count) const
{
    CDeterministicMNList result = *this;
    result.ResetTrackedChanges();
    result.SetBlockHash(pindex->GetBlockHash());
    result.SetHeight(pindex->nHeight);

    // Materialize every target state before mutating the list, then release
    // all child-side unique properties together. Applying updates one at a
    // time is order-dependent when a block transfers an address or key from
    // one masternode to another; inverse application must validate the final
    // parent state atomically instead.
    std::vector<CDeterministicMNCPtr> updated_mns;
    updated_mns.reserve(diff.updatedMNs.size());
    std::vector<uint64_t> updated_ids;
    updated_ids.reserve(diff.updatedMNs.size());
    for (const auto& [internal_id, _] : diff.updatedMNs) {
        updated_ids.emplace_back(internal_id);
    }
    std::sort(updated_ids.begin(), updated_ids.end());
    for (const uint64_t internal_id : updated_ids) {
        const auto current{result.GetMNByInternalId(internal_id)};
        if (!current) {
            throw(std::runtime_error(strprintf(
                "%s: can't find an updated masternode, id=%d",
                __func__, internal_id)));
        }
        auto target{std::make_shared<CDeterministicMN>(*current)};
        auto target_state{
            std::make_shared<CDeterministicMNState>(*current->pdmnState)};
        diff.updatedMNs.at(internal_id).ApplyToState(*target_state);
        target->pdmnState = std::move(target_state);
        updated_mns.emplace_back(std::move(target));
    }

    for (const auto& id : diff.removedMns) {
        auto dmn = result.GetMNByInternalId(id);
        if (!dmn) {
            throw(std::runtime_error(strprintf("%s: can't find a removed masternode, id=%d", __func__, id)));
        }
        result.RemoveMN(dmn->proTxHash);
    }
    for (const auto& dmn : updated_mns) {
        const auto current{result.GetMNByInternalId(dmn->GetInternalId())};
        if (!current) {
            throw(std::runtime_error(strprintf(
                "%s: can't remove an updated masternode, id=%d",
                __func__, dmn->GetInternalId())));
        }
        result.RemoveMN(current->proTxHash);
    }
    for (const auto& dmn : diff.addedMNs) {
        result.AddMN(dmn);
    }
    for (const auto& dmn : updated_mns) {
        result.AddMN(dmn, /*fBumpTotalCount=*/false);
    }

    if (total_registered_count) {
        uint64_t minimum_total{0};
        result.ForEachMN(false, [&minimum_total](const CDeterministicMN& dmn) {
            if (dmn.GetInternalId() == std::numeric_limits<uint64_t>::max()) {
                throw std::runtime_error(
                    "deterministic masternode internal ID overflow");
            }
            minimum_total = std::max(minimum_total,
                                     dmn.GetInternalId() + 1);
        });
        if (minimum_total > *total_registered_count) {
            throw std::runtime_error(
                "deterministic masternode total count underflow");
        }
        result.nTotalRegisteredCount = *total_registered_count;
    }

    result.ResetTrackedChanges();
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
    m_tracked_changes.emplace(dmn->proTxHash);
    m_pq_legacy_state_hash.reset();
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
    m_tracked_changes.emplace(oldDmn.proTxHash);
    m_pq_legacy_state_hash.reset();
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
    m_tracked_changes.emplace(proTxHash);
    m_pq_legacy_state_hash.reset();
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

        // SYSCOIN: Anchor validation must observe the exact prepared PQ root,
        // while rejected and check-only blocks must publish no registry state.
        uint256 pq_registry_state_root;
        llmq::pq::PQRegistryManager* pq_registry{nullptr};
        llmq::pq::PQRegistryPreparedBlock pq_registry_prepared;
        llmq::pq::PQRegistryError pq_registry_error;
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
            pq_registry = GetOrCreatePQRegistry(registry_open_error);
            if (pq_registry == nullptr) {
                LogPrintf("%s -- %s\n", __func__, registry_open_error);
                return _state.Error("failed-pq-registry-open");
            }
            const auto callbacks = MakePQRegistryCallbacks(
                oldList, newList, consensusParams.hashGenesisBlock);
            const auto net_removed_pro_tx_hashes{
                newList.BuildTrackedNetRemovedProTxHashes(oldList)};
            if (!pq_registry->PrepareBlock(
                    block, nHeight, callbacks, net_removed_pro_tx_hashes,
                    pq_registry_prepared, pq_registry_error)) {
                LogPrintf("%s -- PQ registry rejected height=%d tx=%u protx=%s result=%s state_result=%u\n",
                          __func__, nHeight,
                          static_cast<unsigned>(pq_registry_error.transaction_index),
                          pq_registry_error.pro_tx_hash.ToString(),
                          std::string{llmq::pq::PQRegistryResultString(
                              pq_registry_error.result)},
                          static_cast<unsigned>(pq_registry_error.state_result));
                return _state.Invalid(
                    BlockValidationResult::BLOCK_CONSENSUS,
                    strprintf("bad-pq-%s",
                              std::string{llmq::pq::PQRegistryResultString(
                              pq_registry_error.result)}));
            }
            pq_registry_state_root =
                pq_registry_prepared.ConsensusStateRoot();
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

        const uint256 dmn_state_hash{newList.GetOrComputePQLegacyStateHash(
            consensusParams.hashGenesisBlock)};
        if (!Consensus::CheckPQLegacyState(
                consensusParams, nHeight, dmn_state_hash,
                pq_registry_state_root)) {
            return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                                  "bad-pq-legacy-state");
        }

        if (fJustCheck) {
            return true;
        }

        if (pq_registry != nullptr) {
            bool committed{false};
            try {
                committed = pq_registry->CommitPreparedBlock(
                    pq_registry_prepared, pq_registry_error);
            } catch (const std::exception& exception) {
                LogPrintf("%s -- PQ registry commit exception height=%d block=%s: %s\n",
                          __func__, nHeight,
                          pindex->GetBlockHash().ToString(), exception.what());
                return _state.Error("failed-pq-registry-commit");
            } catch (...) {
                LogPrintf("%s -- PQ registry commit exception height=%d block=%s\n",
                          __func__, nHeight,
                          pindex->GetBlockHash().ToString());
                return _state.Error("failed-pq-registry-commit");
            }
            if (!committed) {
                LogPrintf("%s -- PQ registry commit failed height=%d block=%s result=%s\n",
                          __func__, nHeight,
                          pindex->GetBlockHash().ToString(),
                          std::string{llmq::pq::PQRegistryResultString(
                              pq_registry_error.result)});
                return _state.Error(strprintf(
                    "failed-pq-registry-commit-%s",
                    std::string{llmq::pq::PQRegistryResultString(
                        pq_registry_error.result)}));
            }
        }

        if (pindex->pprev != nullptr &&
            pindex->pprev->nHeight >= consensusParams.DIP0003Height &&
            !CommitInverseJournal(pindex, newList, oldList,
                                  dmn_state_hash)) {
            return _state.Error("failed-dmn-inverse-persist");
        }
        newList.ResetTrackedChanges();

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
    const auto& consensus{Params().GetConsensus()};
    if (pindex->nHeight < consensus.DIP0003Height) return true;
    if (pindex->pprev == nullptr) return false;

    llmq::pq::PQRegistryConfig pq_config;
    const auto pq_deployment = llmq::pq::GetPQRegistryConfig(
        consensus, pq_config);
    if (pq_deployment ==
        llmq::pq::PQRegistryDeploymentResult::INVALID_CONFIGURATION) {
        return false;
    }

    CDeterministicMNList curList;
    CDeterministicMNList prevList;
    try {
        if (!m_evoDb->ReadCache(pindex->GetBlockHash(), curList) ||
            curList.IsNull() || curList.GetHeight() != pindex->nHeight ||
            curList.GetBlockHash() != pindex->GetBlockHash()) {
            LogPrintf("%s -- missing or invalid current deterministic-MN "
                      "snapshot at height=%d block=%s\n",
                      __func__, pindex->nHeight,
                      pindex->GetBlockHash().ToString());
            return false;
        }

        if (pindex->pprev->nHeight < consensus.DIP0003Height) {
            prevList = CDeterministicMNList{};
        } else {
            CDeterministicMNList reconstructed;
            if (!LoadAndVerifyInverseJournal(pindex, curList,
                                             reconstructed)) {
                return false;
            }

            if (m_evoDb->ReadCache(pindex->pprev->GetBlockHash(), prevList)) {
                if (prevList.IsNull() ||
                    prevList.GetHeight() != pindex->pprev->nHeight ||
                    prevList.GetBlockHash() !=
                        pindex->pprev->GetBlockHash() ||
                    prevList.GetOrComputePQLegacyStateHash(
                        consensus.hashGenesisBlock) !=
                        reconstructed.GetOrComputePQLegacyStateHash(
                            consensus.hashGenesisBlock)) {
                    LogPrintf("%s -- persisted deterministic-MN parent "
                              "conflicts with inverse journal at height=%d "
                              "block=%s\n",
                              __func__, pindex->pprev->nHeight,
                              pindex->pprev->GetBlockHash().ToString());
                    return false;
                }
            } else {
                prevList = std::move(reconstructed);
                // The recovered parent becomes the next disconnect's child.
                // Publish it before returning so the ordinary UTXO durability
                // barrier can order both states together.
                if (!m_evoDb->WriteThrough(
                        pindex->pprev->GetBlockHash(), prevList,
                        /*fSync=*/false)) {
                    return false;
                }
            }
        }
    } catch (const std::exception& exception) {
        LogPrintf("%s -- deterministic-MN undo preparation failed at "
                  "height=%d block=%s: %s\n",
                  __func__, pindex->nHeight,
                  pindex->GetBlockHash().ToString(), exception.what());
        return false;
    }

    // Validate and recover the DMN parent before rolling back any other
    // branch-bound database. A bad journal therefore fails closed without
    // leaving the registry one block behind the active chain.
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

    CDeterministicMNListDiff inversedDiff;
    curList.BuildDiff(prevList, inversedDiff, inversedDiffNEVMAddress);
    if(inversedDiff.HasChanges()) {
        GetMainSignals().NotifyMasternodeListChanged(true, prevList, inversedDiff);
    }
    // SYSCOIN always update interface
    uiInterface.NotifyMasternodeListChanged(prevList);
    return true;
}

bool CDeterministicMNManager::BuildNewListFromBlock(const CBlock& block, const CBlockIndex* pindexPrev, BlockValidationState& _state, const CCoinsViewCache& view, CDeterministicMNList& mnListRet, CDeterministicMNList& oldList, const llmq::CFinalCommitmentTxPayload& legacy_commitment)
{

    int nHeight = pindexPrev->nHeight + 1;

    oldList = GetListForBlock(pindexPrev);
    CDeterministicMNList newList = oldList;
    newList.ResetTrackedChanges();
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
    const auto payment_eligibility{Consensus::CheckPQPaymentEligibility(
        Params().GetConsensus(), nHeight)};
    if (payment_eligibility ==
        Consensus::PQPaymentEligibilityResult::INVALID_CONFIGURATION) {
        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              "bad-pq-payment-eligibility-configuration");
    }
    CDeterministicMNCPtr payee;
    if (!GetMNPayeeForBlock(pindexPrev, payee)) {
        return _state.Error("failed-pq-payment-eligibility-state");
    }
    if (payment_eligibility ==
            Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED &&
        !payee) {
        return _state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                              "bad-pq-no-payment-eligible-mn");
    }
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
        if (Consensus::CheckPQLegacyReplay(consensus, nHeight) !=
            Consensus::PQLegacyReplayResult::ALLOWED) {
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
            replay.minimum_size <= 0 ||
            replay.minimum_size > replay.size ||
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
                static_cast<std::size_t>(replay.minimum_size),
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
                        llmq::pq::PQRegistryReadView parent_snapshot;
                        std::string registry_error;
                        if (!GetPQRegistryReadView(pindexPrev, parent_snapshot, registry_error)) {
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
            
                // SYSCOIN: The released lazy BLS wrapper compared the group
                // value when a v1 key was reserialized as v2. Preserve that
                // replay semantic without restoring BLS group operations.
                const bool same_legacy_operator_key{
                    AreLegacyBLSPublicKeyEncodingsEquivalent(
                        newState->pubKeyOperator,
                        newState->nVersion == CProRegTx::LEGACY_BLS_VERSION,
                        proTx.pubKeyOperator,
                        proTx.nVersion == CProUpRegTx::LEGACY_BLS_VERSION)};
                if (proTx.nVersion <= CProUpRegTx::BASIC_BLS_VERSION &&
                    !same_legacy_operator_key) {
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

bool CDeterministicMNManager::GetPQRegistryReadView(
    const CBlockIndex* pindex,
    llmq::pq::PQRegistryReadView& view,
    std::string& error) const
{
    view = {};
    if (pindex == nullptr) {
        error = "pq-registry-null-block-index";
        return false;
    }
    auto* registry = GetOrCreatePQRegistry(error);
    if (registry == nullptr) return false;

    llmq::pq::PQRegistryError registry_error;
    const uint256 previous_hash{
        pindex->pprev == nullptr ? uint256{}
                                 : pindex->pprev->GetBlockHash()};
    if (!registry->GetReadView(pindex->GetBlockHash(), previous_hash,
                               pindex->nHeight, view, registry_error)) {
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

bool CDeterministicMNManager::VerifyInverseJournalTipSeal(
    const CBlockIndex* tip)
{
    if (tip == nullptr) return false;
    const auto& consensus{Params().GetConsensus()};
    if (tip->nHeight < consensus.DIP0003Height) return true;

    CDeterministicMNList tip_snapshot;
    if (!m_evoDb->ReadCache(tip->GetBlockHash(), tip_snapshot) ||
        tip_snapshot.IsNull() || tip_snapshot.GetHeight() != tip->nHeight ||
        tip_snapshot.GetBlockHash() != tip->GetBlockHash()) {
        return false;
    }
    if (tip->nHeight == consensus.DIP0003Height) {
        return EnsureRetainedSnapshotWindow(tip, tip_snapshot);
    }
    if (tip->pprev == nullptr) return false;

    try {
        CDeterministicMNList reconstructed_parent;
        if (!LoadAndVerifyInverseJournal(tip, tip_snapshot,
                                         reconstructed_parent)) {
            return false;
        }
        CDeterministicMNList persisted_parent;
        if (!m_evoDb->ReadCache(tip->pprev->GetBlockHash(),
                                persisted_parent)) {
            // A completed deep disconnect can leave the active tip as the
            // oldest materialized snapshot. The verified inverse above is
            // sufficient to reconstruct its parent on demand; an existing
            // but unreadable parent remains a fail-closed database error.
            if (m_evoDb->ExistsCache(tip->pprev->GetBlockHash())) {
                return false;
            }
            return EnsureRetainedSnapshotWindow(tip, tip_snapshot);
        }
        if (persisted_parent.IsNull() ||
            persisted_parent.GetHeight() != tip->pprev->nHeight ||
            persisted_parent.GetBlockHash() != tip->pprev->GetBlockHash()) {
            return false;
        }
        return persisted_parent.GetOrComputePQLegacyStateHash(
                   consensus.hashGenesisBlock) ==
               reconstructed_parent.GetOrComputePQLegacyStateHash(
                   consensus.hashGenesisBlock) &&
               EnsureRetainedSnapshotWindow(tip, tip_snapshot);
    } catch (const std::exception& exception) {
        LogPrintf("%s -- deterministic-MN inverse tip-seal verification "
                  "failed at height=%d block=%s: %s\n",
                  __func__, tip->nHeight, tip->GetBlockHash().ToString(),
                  exception.what());
        return false;
    }
}

bool CDeterministicMNManager::CorruptInverseJournalForTesting(
    const uint256& child_hash)
{
    CDeterministicMNListInverse inverse;
    if (!m_inverse_journal->ReadCache(child_hash, inverse)) return false;
    inverse.parent_state_hash.begin()[0] ^= 1;
    inverse.history_commitment = GetDMNInverseHistoryCommitment(inverse);
    return inverse.IsStructurallyValid() &&
           m_inverse_journal->WriteThrough(child_hash, inverse,
                                           /*fSync=*/true);
}

bool CDeterministicMNManager::GetInverseJournalEntryStatsForTesting(
    const uint256& child_hash,
    InverseJournalEntryStatsForTesting& stats)
{
    try {
        CDeterministicMNListInverse inverse;
        if (!m_inverse_journal->ReadCache(child_hash, inverse)) return false;
        stats.serialized_size = GetSerializeSize(inverse);
        stats.added_mns = inverse.inverse_diff.addedMNs.size();
        stats.updated_mns = inverse.inverse_diff.updatedMNs.size();
        stats.removed_mns = inverse.inverse_diff.removedMns.size();
        return true;
    } catch (const std::exception&) {
        stats = {};
        return false;
    }
}

bool CDeterministicMNManager::EraseInverseJournalEntryForTesting(
    const uint256& child_hash)
{
    try {
        m_inverse_journal->EraseCache(child_hash);
        return m_inverse_journal->FlushCacheToDisk(
            /*CHUNK_ITEMS=*/256, /*fSync=*/true);
    } catch (const std::exception&) {
        return false;
    }
}

void CDeterministicMNManager::FailNextInverseJournalFlushForTesting()
{
    m_inverse_journal->FailNextFlushBatchForTesting();
}

void CDeterministicMNManager::FailNextPQRegistryWriteThroughForTesting()
{
    std::string error;
    auto* registry{GetOrCreatePQRegistry(error)};
    if (registry == nullptr) {
        throw std::runtime_error(error);
    }
    registry->SnapshotDatabase().FailNextWriteThroughForTesting();
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

bool CDeterministicMNManager::DoMaintenance(
    bool bForceFlush,
    bool fSync,
    std::span<const CBlockIndex* const> recovery_snapshot_indexes)
{
    if (!bForceFlush) {
        return true;
    }

    std::vector<const CBlockIndex*> recovery_indexes;
    recovery_indexes.reserve(recovery_snapshot_indexes.size());
    const int dip3_height{Params().GetConsensus().DIP0003Height};
    for (const CBlockIndex* pindex : recovery_snapshot_indexes) {
        if (pindex == nullptr) {
            LogPrintf("%s -- null chainstate recovery marker\n", __func__);
            return false;
        }
        if (pindex->nHeight >= dip3_height) {
            recovery_indexes.push_back(pindex);
        }
    }
    std::sort(recovery_indexes.begin(), recovery_indexes.end(),
              [](const CBlockIndex* left, const CBlockIndex* right) {
                  return left->GetBlockHash() < right->GetBlockHash();
              });
    recovery_indexes.erase(
        std::unique(recovery_indexes.begin(), recovery_indexes.end(),
                    [](const CBlockIndex* left, const CBlockIndex* right) {
                        return left->GetBlockHash() == right->GetBlockHash();
                    }),
        recovery_indexes.end());
    std::vector<uint256> recovery_hashes;
    recovery_hashes.reserve(recovery_indexes.size());
    for (const CBlockIndex* pindex : recovery_indexes) {
        recovery_hashes.push_back(pindex->GetBlockHash());
    }

    // Per-block inverse records use asynchronous write-through. Order their
    // WAL before any maintenance result can be used to publish a chainstate
    // marker or prune the corresponding full parent snapshot.
    if (!m_inverse_journal->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) {
        return false;
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
    const auto verify_recovery_snapshots = [&] {
        for (const CBlockIndex* pindex : recovery_indexes) {
            if (!VerifyPersistedSnapshot(pindex)) {
                LogPrintf("%s -- missing or invalid chainstate recovery "
                          "snapshot at height=%d block=%s\n",
                          __func__, pindex->nHeight,
                          pindex->GetBlockHash().ToString());
                return false;
            }
        }
        return true;
    };
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
            return verify_recovery_snapshots();
        }
        LogPrint(BCLog::SYS,
                 "CDeterministicMNManager::%s maintenance without tip; flushing dirty=%zu erase=%zu only elapsed=%d ms\n",
                 __func__,
                 cache_entry_count,
                 erase_entry_count,
                 ElapsedMillis(maintenance_start));
        return m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync) &&
               verify_recovery_snapshots();
    }

    const uint256 tip_hash = tip->GetBlockHash();
    const size_t cache_entry_count{m_evoDb->GetReadWriteCacheSize()};
    const size_t erase_entry_count{m_evoDb->GetEraseCacheSize()};
    const bool persistent_window_initialized =
        m_persistent_window_initialized.load(std::memory_order_relaxed);

    if (cache_entry_count == 0 && erase_entry_count == 0 &&
        !verify_recovery_snapshots()) {
        return false;
    }
    if (cache_entry_count == 0 && erase_entry_count == 0 &&
        WITH_LOCK(cs, return m_last_maintained_tip == tip_hash &&
                             m_last_maintained_recovery_blocks ==
                                 recovery_hashes)) {
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
    retained_hashes.reserve(LIST_CACHE_SIZE * 2 + recovery_hashes.size());
    CollectRetainedSnapshotHashes(tip, retained_hashes_ordered, retained_hashes);
    // Shared DMN storage serves every initialized chainstate. Background
    // validation and fork-local roster lookups need the same bounded random-
    // access ancestry as the active tip, including around crash-visible
    // CoinsDB heads. Only the active window below is warmed into memory.
    for (const CBlockIndex* recovery_index : recovery_indexes) {
        if (recovery_index->GetBlockHash() == tip_hash) continue;
        std::vector<uint256> recovery_window;
        recovery_window.reserve(LIST_CACHE_SIZE);
        CollectRetainedSnapshotHashes(
            recovery_index, recovery_window, retained_hashes);
    }

    LogPrint(BCLog::SYS,
             "CDeterministicMNManager::%s maintenance start tip=%s height=%d dirty=%zu erase=%zu retained=%zu persistent_window_initialized=%d\n",
             __func__,
             tip_hash.ToString(),
             tip->nHeight,
             cache_entry_count,
             erase_entry_count,
             retained_hashes.size(),
             persistent_window_initialized);

    if ((cache_entry_count != 0 || erase_entry_count != 0) &&
        !m_evoDb->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) {
        return false;
    }
    if ((cache_entry_count != 0 || erase_entry_count != 0) &&
        !verify_recovery_snapshots()) {
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
    if (!verify_recovery_snapshots()) {
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
            m_last_maintained_recovery_blocks = recovery_hashes;
        } else {
            m_last_maintained_tip.SetNull();
            m_last_maintained_recovery_blocks.clear();
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
bool CDeterministicMNManager::FlushCacheToDisk(
    bool bForceFlush,
    bool fSync,
    std::span<const CBlockIndex* const> recovery_snapshot_indexes)
{
    return DoMaintenance(bForceFlush, fSync, recovery_snapshot_indexes);
}

bool CDeterministicMNManager::FlushPendingSnapshotsToDisk(bool fSync)
{
    if (!m_inverse_journal->FlushCacheToDisk(/*CHUNK_ITEMS=*/256, fSync)) {
        return false;
    }
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
