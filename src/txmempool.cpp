// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>

#include <chain.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <logging.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <reverse_iterator.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/result.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validationinterface.h>
// SYSCOIN
#include <util/rbf.h>
#include <evo/pq_providertx.h>
#include <evo/specialtx.h>
#include <evo/providertx.h>
#include <evo/deterministicmns.h>   
extern bool EraseMempoolNEVMData(const std::vector<uint8_t>&, const uint256&);
extern NEVMMintTxSet setMintTxsMempool;
extern std::unordered_map<COutPoint, std::pair<CTransactionRef, CTransactionRef>, SaltedOutpointHasher> mapAssetAllocationConflicts;

#include <cmath>
#include <numeric>
#include <optional>
#include <string_view>
#include <utility>

// SYSCOIN: begin branch-bound PQ provider mempool helpers.
namespace {

constexpr std::size_t MAX_PROVIDER_PACKAGE_TRANSACTIONS{64};

std::optional<llmq::pq::GlobalKeyTxPayload> GetPQGlobalKeyPayload(
    const CTransaction& tx)
{
    if (tx.nVersion != SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY) {
        return std::nullopt;
    }
    std::vector<unsigned char> encoded;
    int output_index{-1};
    llmq::pq::GlobalKeyTxPayload payload;
    if (!GetSyscoinData(tx, encoded, output_index) ||
        !llmq::pq::DecodeGlobalKeyTxPayload(encoded, payload)) {
        return std::nullopt;
    }
    return payload;
}

std::optional<uint256> GetPQOperatorUpdate(const CTransaction& tx)
{
    if (tx.nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY) {
        const auto payload{GetPQGlobalKeyPayload(tx)};
        return payload ? std::optional<uint256>{payload->pro_tx_hash}
                       : std::nullopt;
    }
    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        const auto mutation{DecodeProviderMutationIdentity(tx)};
        if (!mutation || !mutation->is_pq_revocation) {
            return std::nullopt;
        }
        return mutation->pro_tx_hash;
    }
    return std::nullopt;
}

bool IsStandalonePQRegistryTx(const CTransaction& tx)
{
    return tx.nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY;
}

std::optional<uint256> GetProviderMutation(const CTransaction& tx)
{
    const auto mutation{DecodeProviderMutationIdentity(tx)};
    return mutation ? std::optional<uint256>{mutation->pro_tx_hash}
                    : std::nullopt;
}

bool HasPQRegistryCapacity(std::size_t base,
                           std::size_t reserved,
                           std::size_t additional,
                           std::size_t maximum) noexcept
{
    return base <= maximum && reserved <= maximum - base &&
           additional <= maximum - base - reserved;
}

bool IsBranchBoundProviderTransaction(const CTransaction& tx) noexcept
{
    return tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER ||
           tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE ||
           tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR ||
           tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE ||
           tx.nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY;
}

bool SpendsOutpoint(const CTransaction& tx,
                    const COutPoint& outpoint) noexcept
{
    return std::any_of(tx.vin.begin(), tx.vin.end(),
                       [&](const CTxIn& input) {
                           return input.prevout == outpoint;
                       });
}

} // namespace
// SYSCOIN: end branch-bound PQ provider mempool helpers.

bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp)
{
    AssertLockHeld(cs_main);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp.maxInputBlock) {
        // Check whether active_chain is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!active_chain.Contains(lp.maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

void CTxMemPool::UpdateForDescendants(txiter updateIt, cacheMap& cachedDescendants,
                                      const std::set<uint256>& setExclude, std::set<uint256>& descendants_to_remove)
{
    CTxMemPoolEntry::Children stageEntries, descendants;
    stageEntries = updateIt->GetMemPoolChildrenConst();

    while (!stageEntries.empty()) {
        const CTxMemPoolEntry& descendant = *stageEntries.begin();
        descendants.insert(descendant);
        stageEntries.erase(descendant);
        const CTxMemPoolEntry::Children& children = descendant.GetMemPoolChildrenConst();
        for (const CTxMemPoolEntry& childEntry : children) {
            cacheMap::iterator cacheIt = cachedDescendants.find(mapTx.iterator_to(childEntry));
            if (cacheIt != cachedDescendants.end()) {
                // We've already calculated this one, just add the entries for this set
                // but don't traverse again.
                for (txiter cacheEntry : cacheIt->second) {
                    descendants.insert(*cacheEntry);
                }
            } else if (!descendants.count(childEntry)) {
                // Schedule for later processing
                stageEntries.insert(childEntry);
            }
        }
    }
    // descendants now contains all in-mempool descendants of updateIt.
    // Update and add to cached descendant map
    int32_t modifySize = 0;
    CAmount modifyFee = 0;
    int64_t modifyCount = 0;
    for (const CTxMemPoolEntry& descendant : descendants) {
        if (!setExclude.count(descendant.GetTx().GetHash())) {
            modifySize += descendant.GetTxSize();
            modifyFee += descendant.GetModifiedFee();
            modifyCount++;
            cachedDescendants[updateIt].insert(mapTx.iterator_to(descendant));
            // Update ancestor state for each descendant
            mapTx.modify(mapTx.iterator_to(descendant), [=](CTxMemPoolEntry& e) {
              e.UpdateAncestorState(updateIt->GetTxSize(), updateIt->GetModifiedFee(), 1, updateIt->GetSigOpCost());
            });
            // Don't directly remove the transaction here -- doing so would
            // invalidate iterators in cachedDescendants. Mark it for removal
            // by inserting into descendants_to_remove.
            if (descendant.GetCountWithAncestors() > uint64_t(m_limits.ancestor_count) || descendant.GetSizeWithAncestors() > m_limits.ancestor_size_vbytes) {
                descendants_to_remove.insert(descendant.GetTx().GetHash());
            }
        }
    }
    mapTx.modify(updateIt, [=](CTxMemPoolEntry& e) { e.UpdateDescendantState(modifySize, modifyFee, modifyCount); });
}

void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<uint256>& vHashesToUpdate)
{
    AssertLockHeld(cs);
    // For each entry in vHashesToUpdate, store the set of in-mempool, but not
    // in-vHashesToUpdate transactions, so that we don't have to recalculate
    // descendants when we come across a previously seen entry.
    cacheMap mapMemPoolDescendantsToUpdate;

    // Use a set for lookups into vHashesToUpdate (these entries are already
    // accounted for in the state of their ancestors)
    std::set<uint256> setAlreadyIncluded(vHashesToUpdate.begin(), vHashesToUpdate.end());

    std::set<uint256> descendants_to_remove;

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    // This maximizes the benefit of the descendant cache and guarantees that
    // CTxMemPoolEntry::m_children will be updated, an assumption made in
    // UpdateForDescendants.
    for (const uint256 &hash : reverse_iterate(vHashesToUpdate)) {
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        // First calculate the children, and update CTxMemPoolEntry::m_children to
        // include them, and update their CTxMemPoolEntry::m_parents to include this tx.
        // we cache the in-mempool children to avoid duplicate updates
        {
            WITH_FRESH_EPOCH(m_epoch);
            for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
                const uint256 &childHash = iter->second->GetHash();
                txiter childIter = mapTx.find(childHash);
                assert(childIter != mapTx.end());
                // We can skip updating entries we've encountered before or that
                // are in the block (which are already accounted for).
                if (!visited(childIter) && !setAlreadyIncluded.count(childHash)) {
                    UpdateChild(it, childIter, true);
                    UpdateParent(childIter, it, true);
                }
            }
        } // release epoch guard for UpdateForDescendants
        UpdateForDescendants(it, mapMemPoolDescendantsToUpdate, setAlreadyIncluded, descendants_to_remove);
    }

    for (const auto& txid : descendants_to_remove) {
        // This txid may have been removed already in a prior call to removeRecursive.
        // Therefore we ensure it is not yet removed already.
        if (const std::optional<txiter> txiter = GetIter(txid)) {
            removeRecursive((*txiter)->GetTx(), MemPoolRemovalReason::SIZELIMIT);
        }
    }
}

util::Result<CTxMemPool::setEntries> CTxMemPool::CalculateAncestorsAndCheckLimits(
    int64_t entry_size,
    size_t entry_count,
    CTxMemPoolEntry::Parents& staged_ancestors,
    const Limits& limits) const
{
    int64_t totalSizeWithAncestors = entry_size;
    setEntries ancestors;

    while (!staged_ancestors.empty()) {
        const CTxMemPoolEntry& stage = staged_ancestors.begin()->get();
        txiter stageit = mapTx.iterator_to(stage);

        ancestors.insert(stageit);
        staged_ancestors.erase(stage);
        totalSizeWithAncestors += stageit->GetTxSize();

        if (stageit->GetSizeWithDescendants() + entry_size > limits.descendant_size_vbytes) {
            return util::Error{Untranslated(strprintf("exceeds descendant size limit for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limits.descendant_size_vbytes))};
        } else if (static_cast<uint64_t>(stageit->GetCountWithDescendants() + entry_count) > static_cast<uint64_t>(limits.descendant_count)) {
            return util::Error{Untranslated(strprintf("too many descendants for tx %s [limit: %u]", stageit->GetTx().GetHash().ToString(), limits.descendant_count))};
        } else if (totalSizeWithAncestors > limits.ancestor_size_vbytes) {
            return util::Error{Untranslated(strprintf("exceeds ancestor size limit [limit: %u]", limits.ancestor_size_vbytes))};
        }

        const CTxMemPoolEntry::Parents& parents = stageit->GetMemPoolParentsConst();
        for (const CTxMemPoolEntry& parent : parents) {
            txiter parent_it = mapTx.iterator_to(parent);

            // If this is a new ancestor, add it.
            if (ancestors.count(parent_it) == 0) {
                staged_ancestors.insert(parent);
            }
            if (staged_ancestors.size() + ancestors.size() + entry_count > static_cast<uint64_t>(limits.ancestor_count)) {
                return util::Error{Untranslated(strprintf("too many unconfirmed ancestors [limit: %u]", limits.ancestor_count))};
            }
        }
    }

    return ancestors;
}

bool CTxMemPool::CheckPackageLimits(const Package& package,
                                    const int64_t total_vsize,
                                    std::string &errString) const
{
    size_t pack_count = package.size();

    // Package itself is busting mempool limits; should be rejected even if no staged_ancestors exist
    if (pack_count > static_cast<uint64_t>(m_limits.ancestor_count)) {
        errString = strprintf("package count %u exceeds ancestor count limit [limit: %u]", pack_count, m_limits.ancestor_count);
        return false;
    } else if (pack_count > static_cast<uint64_t>(m_limits.descendant_count)) {
        errString = strprintf("package count %u exceeds descendant count limit [limit: %u]", pack_count, m_limits.descendant_count);
        return false;
    } else if (total_vsize > m_limits.ancestor_size_vbytes) {
        errString = strprintf("package size %u exceeds ancestor size limit [limit: %u]", total_vsize, m_limits.ancestor_size_vbytes);
        return false;
    } else if (total_vsize > m_limits.descendant_size_vbytes) {
        errString = strprintf("package size %u exceeds descendant size limit [limit: %u]", total_vsize, m_limits.descendant_size_vbytes);
        return false;
    }

    CTxMemPoolEntry::Parents staged_ancestors;
    for (const auto& tx : package) {
        for (const auto& input : tx->vin) {
            std::optional<txiter> piter = GetIter(input.prevout.hash);
            if (piter) {
                staged_ancestors.insert(**piter);
                if (staged_ancestors.size() + package.size() > static_cast<uint64_t>(m_limits.ancestor_count)) {
                    errString = strprintf("too many unconfirmed parents [limit: %u]", m_limits.ancestor_count);
                    return false;
                }
            }
        }
    }
    // When multiple transactions are passed in, the ancestors and descendants of all transactions
    // considered together must be within limits even if they are not interdependent. This may be
    // stricter than the limits for each individual transaction.
    const auto ancestors{CalculateAncestorsAndCheckLimits(total_vsize, package.size(),
                                                          staged_ancestors, m_limits)};
    // It's possible to overestimate the ancestor/descendant totals.
    if (!ancestors.has_value()) errString = "possibly " + util::ErrorString(ancestors).original;
    return ancestors.has_value();
}

util::Result<CTxMemPool::setEntries> CTxMemPool::CalculateMemPoolAncestors(
    const CTxMemPoolEntry &entry,
    const Limits& limits,
    bool fSearchForParents /* = true */) const
{
    CTxMemPoolEntry::Parents staged_ancestors;
    const CTransaction &tx = entry.GetTx();

    if (fSearchForParents) {
        // Get parents of this transaction that are in the mempool
        // GetMemPoolParents() is only valid for entries in the mempool, so we
        // iterate mapTx to find parents.
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            std::optional<txiter> piter = GetIter(tx.vin[i].prevout.hash);
            if (piter) {
                staged_ancestors.insert(**piter);
                if (staged_ancestors.size() + 1 > static_cast<uint64_t>(limits.ancestor_count)) {
                    return util::Error{Untranslated(strprintf("too many unconfirmed parents [limit: %u]", limits.ancestor_count))};
                }
            }
        }
    } else {
        // If we're not searching for parents, we require this to already be an
        // entry in the mempool and use the entry's cached parents.
        txiter it = mapTx.iterator_to(entry);
        staged_ancestors = it->GetMemPoolParentsConst();
    }

    return CalculateAncestorsAndCheckLimits(entry.GetTxSize(), /*entry_count=*/1, staged_ancestors,
                                            limits);
}

CTxMemPool::setEntries CTxMemPool::AssumeCalculateMemPoolAncestors(
    std::string_view calling_fn_name,
    const CTxMemPoolEntry &entry,
    const Limits& limits,
    bool fSearchForParents /* = true */) const
{
    auto result{CalculateMemPoolAncestors(entry, limits, fSearchForParents)};
    if (!Assume(result)) {
        LogPrintLevel(BCLog::MEMPOOL, BCLog::Level::Error, "%s: CalculateMemPoolAncestors failed unexpectedly, continuing with empty ancestor set (%s)\n",
                      calling_fn_name, util::ErrorString(result).original);
    }
    return std::move(result).value_or(CTxMemPool::setEntries{});
}

void CTxMemPool::UpdateAncestorsOf(bool add, txiter it, setEntries &setAncestors)
{
    const CTxMemPoolEntry::Parents& parents = it->GetMemPoolParentsConst();
    // add or remove this tx as a child of each parent
    for (const CTxMemPoolEntry& parent : parents) {
        UpdateChild(mapTx.iterator_to(parent), it, add);
    }
    const int32_t updateCount = (add ? 1 : -1);
    const int32_t updateSize{updateCount * it->GetTxSize()};
    const CAmount updateFee = updateCount * it->GetModifiedFee();
    for (txiter ancestorIt : setAncestors) {
        mapTx.modify(ancestorIt, [=](CTxMemPoolEntry& e) { e.UpdateDescendantState(updateSize, updateFee, updateCount); });
    }
}

void CTxMemPool::UpdateEntryForAncestors(txiter it, const setEntries &setAncestors)
{
    int64_t updateCount = setAncestors.size();
    int64_t updateSize = 0;
    CAmount updateFee = 0;
    int64_t updateSigOpsCost = 0;
    for (txiter ancestorIt : setAncestors) {
        updateSize += ancestorIt->GetTxSize();
        updateFee += ancestorIt->GetModifiedFee();
        updateSigOpsCost += ancestorIt->GetSigOpCost();
    }
    mapTx.modify(it, [=](CTxMemPoolEntry& e){ e.UpdateAncestorState(updateSize, updateFee, updateCount, updateSigOpsCost); });
}

void CTxMemPool::UpdateChildrenForRemoval(txiter it)
{
    const CTxMemPoolEntry::Children& children = it->GetMemPoolChildrenConst();
    for (const CTxMemPoolEntry& updateIt : children) {
        UpdateParent(mapTx.iterator_to(updateIt), it, false);
    }
}

void CTxMemPool::UpdateForRemoveFromMempool(const setEntries &entriesToRemove, bool updateDescendants)
{
    // For each entry, walk back all ancestors and decrement size associated with this
    // transaction
    if (updateDescendants) {
        // updateDescendants should be true whenever we're not recursively
        // removing a tx and all its descendants, eg when a transaction is
        // confirmed in a block.
        // Here we only update statistics and not data in CTxMemPool::Parents
        // and CTxMemPoolEntry::Children (which we need to preserve until we're
        // finished with all operations that need to traverse the mempool).
        for (txiter removeIt : entriesToRemove) {
            setEntries setDescendants;
            CalculateDescendants(removeIt, setDescendants);
            setDescendants.erase(removeIt); // don't update state for self
            int32_t modifySize = -removeIt->GetTxSize();
            CAmount modifyFee = -removeIt->GetModifiedFee();
            int modifySigOps = -removeIt->GetSigOpCost();
            for (txiter dit : setDescendants) {
                mapTx.modify(dit, [=](CTxMemPoolEntry& e){ e.UpdateAncestorState(modifySize, modifyFee, -1, modifySigOps); });
            }
        }
    }
    for (txiter removeIt : entriesToRemove) {
        const CTxMemPoolEntry &entry = *removeIt;
        // Since this is a tx that is already in the mempool, we can call CMPA
        // with fSearchForParents = false.  If the mempool is in a consistent
        // state, then using true or false should both be correct, though false
        // should be a bit faster.
        // However, if we happen to be in the middle of processing a reorg, then
        // the mempool can be in an inconsistent state.  In this case, the set
        // of ancestors reachable via GetMemPoolParents()/GetMemPoolChildren()
        // will be the same as the set of ancestors whose packages include this
        // transaction, because when we add a new transaction to the mempool in
        // addUnchecked(), we assume it has no children, and in the case of a
        // reorg where that assumption is false, the in-mempool children aren't
        // linked to the in-block tx's until UpdateTransactionsFromBlock() is
        // called.
        // So if we're being called during a reorg, ie before
        // UpdateTransactionsFromBlock() has been called, then
        // GetMemPoolParents()/GetMemPoolChildren() will differ from the set of
        // mempool parents we'd calculate by searching, and it's important that
        // we use the cached notion of ancestor transactions as the set of
        // things to update for removal.
        auto ancestors{AssumeCalculateMemPoolAncestors(__func__, entry, Limits::NoLimits(), /*fSearchForParents=*/false)};
        // Note that UpdateAncestorsOf severs the child links that point to
        // removeIt in the entries for the parents of removeIt.
        UpdateAncestorsOf(false, removeIt, ancestors);
    }
    // After updating all the ancestor sizes, we can now sever the link between each
    // transaction being removed and any mempool children (ie, update CTxMemPoolEntry::m_parents
    // for each direct child of a transaction being removed).
    for (txiter removeIt : entriesToRemove) {
        UpdateChildrenForRemoval(removeIt);
    }
}

void CTxMemPoolEntry::UpdateDescendantState(int32_t modifySize, CAmount modifyFee, int64_t modifyCount)
{
    nSizeWithDescendants += modifySize;
    assert(nSizeWithDescendants > 0);
    nModFeesWithDescendants = SaturatingAdd(nModFeesWithDescendants, modifyFee);
    m_count_with_descendants += modifyCount;
    assert(m_count_with_descendants > 0);
}

void CTxMemPoolEntry::UpdateAncestorState(int32_t modifySize, CAmount modifyFee, int64_t modifyCount, int64_t modifySigOps)
{
    nSizeWithAncestors += modifySize;
    assert(nSizeWithAncestors > 0);
    nModFeesWithAncestors = SaturatingAdd(nModFeesWithAncestors, modifyFee);
    m_count_with_ancestors += modifyCount;
    assert(m_count_with_ancestors > 0);
    nSigOpCostWithAncestors += modifySigOps;
    assert(int(nSigOpCostWithAncestors) >= 0);
}

CTxMemPool::CTxMemPool(const Options& opts)
    : m_check_ratio{opts.check_ratio},
      minerPolicyEstimator{opts.estimator},
      m_max_size_bytes{opts.max_size_bytes},
      m_expiry{opts.expiry},
      m_incremental_relay_feerate{opts.incremental_relay_feerate},
      m_min_relay_feerate{opts.min_relay_feerate},
      m_dust_relay_feerate{opts.dust_relay_feerate},
      m_permit_bare_multisig{opts.permit_bare_multisig},
      m_max_datacarrier_bytes{opts.max_datacarrier_bytes},
      m_require_standard{opts.require_standard},
      m_full_rbf{opts.full_rbf},
      m_limits{opts.limits}
{
}

bool CTxMemPool::isSpent(const COutPoint& outpoint) const
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    nTransactionsUpdated += n;
}
// SYSCOIN: Extend Bitcoin mempool insertion with branch-bound PQ reservations.
bool CTxMemPool::addUnchecked(
    const CTxMemPoolEntry& entry,
    setEntries& setAncestors,
    bool validFeeEstimate,
    const CBlockIndex* pq_registry_tip,
    std::optional<COutPoint> pq_operator_collateral)
{
    // Add to memory pool without checking anything.
    // Used by AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    const CTransaction& tx = entry.GetTx();
    const auto pq_operator_hash{GetPQOperatorUpdate(tx)};
    if (pq_registry_tip != nullptr && pq_operator_hash &&
        !pq_operator_collateral) {
        LogPrintf("%s: refusing to add PQ provider transaction %s without "
                  "resolved collateral\n",
                  __func__, tx.GetHash().ToString());
        return false;
    }
    indexed_transaction_set::iterator newit = mapTx.insert(entry).first;

    // Update transaction for any feeDelta created by PrioritiseTransaction
    CAmount delta{0};
    ApplyDelta(entry.GetTx().GetHash(), delta);
    // The following call to UpdateModifiedFee assumes no previous fee modifications
    Assume(entry.GetFee() == entry.GetModifiedFee());
    if (delta) {
        mapTx.modify(newit, [&delta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(delta); });
    }

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    std::set<uint256> setParentTransactions;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, &tx));
        setParentTransactions.insert(tx.vin[i].prevout.hash);
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    // Update ancestors with information about this tx
    for (const auto& pit : GetIterSet(setParentTransactions)) {
            UpdateParent(newit, pit, true);
    }
    UpdateAncestorsOf(true, newit, setAncestors);
    UpdateEntryForAncestors(newit, setAncestors);

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    m_total_fee += entry.GetFee();
    if (minerPolicyEstimator) {
        minerPolicyEstimator->processTransaction(entry, validFeeEstimate);
    }

    vTxHashes.emplace_back(tx.GetWitnessHash(), newit);
    newit->vTxHashesIdx = vTxHashes.size() - 1;
    // SYSCOIN
    // Invalid ProTxes should never get this far because transactions should be
    // fully checked by AcceptToMemoryPool() at this point, so we just assume that
    // everything is fine here.
    const uint256 tx_hash{tx.GetHash()};
    if (const auto global{GetPQGlobalKeyPayload(tx)}) {
        PQGlobalReservation reservation;
        reservation.pro_tx_hash = global->pro_tx_hash;
        reservation.public_key = global->candidate.public_key;
        const auto& commitment{global->candidate.child_key_commitment};
        reservation.commitment = {
            .version = commitment.version,
            .profile = commitment.profile,
            .usage_cap = commitment.usage_cap,
            .depth = commitment.depth,
            .generation = commitment.generation,
            .first_epoch = commitment.first_epoch,
            .tree_id = commitment.tree_id,
            .root = commitment.root,
        };

        if (pq_registry_tip != nullptr && deterministicMNManager) {
            const std::array<uint256, 1> requested{global->pro_tx_hash};
            llmq::pq::PQRegistryMempoolView view;
            std::string error;
            if (deterministicMNManager->GetPQRegistryMempoolView(
                    pq_registry_tip, requested, view, error)) {
                const auto* current{view.FindOperator(global->pro_tx_hash)};
                if (current != nullptr) {
                    reservation.introduces_operator =
                        current->state_exists == 0;
                }
            } else {
                LogPrint(BCLog::MEMPOOL,
                         "%s: failed to classify PQ reservation %s: %s\n",
                         __func__, tx_hash.ToString(), error);
            }
        }
        mapPQGlobalKeys.emplace(reservation.public_key, tx_hash);
        const auto [position, inserted]{mapPQGlobalReservations.emplace(
            tx_hash, std::move(reservation))};
        if (inserted) {
            m_pq_operator_introductions +=
                position->second.introduces_operator ? 1 : 0;
        }
    }
    if (pq_operator_hash) {
        mapPQOperatorUpdates.emplace(*pq_operator_hash, tx_hash);
        if (pq_operator_collateral) {
            mapPQUpdateCollaterals.emplace(*pq_operator_collateral, tx_hash);
            mapPQUpdateCollateralByTx.emplace(tx_hash,
                                               *pq_operator_collateral);
        }
        if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
            mapPQRevocations.emplace(*pq_operator_hash, tx_hash);
        }
        if (IsStandalonePQRegistryTx(tx)) {
            mapProTxRefs.emplace(*pq_operator_hash, tx_hash);
        }
    }
    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
        CProRegTx proTx;
        if(GetTxPayload(tx, proTx)) {
            if (!proTx.collateralOutpoint.hash.IsNull()) {
                mapProTxRefs.emplace(tx_hash, proTx.collateralOutpoint.hash);
            }
            mapProTxAddresses.emplace(proTx.addr, tx_hash);
            mapProTxPubKeyIDs.emplace(proTx.keyIDOwner, tx_hash);
            if (!proTx.collateralOutpoint.hash.IsNull()) {
                mapProTxCollaterals.emplace(proTx.collateralOutpoint, tx_hash);
            } else {
                mapProTxCollaterals.emplace(COutPoint(tx_hash, proTx.collateralOutpoint.n), tx_hash);
            }
        }
    } else if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if(GetTxPayload(tx, proTx)) {
            mapProTxRefs.emplace(proTx.proTxHash, tx_hash);
            mapProTxAddresses.emplace(proTx.addr, tx_hash);
            if(!proTx.vchNEVMAddress.empty()) {
                mapProTxNEVMAddresses.emplace(proTx.vchNEVMAddress, tx_hash);
            }
        }
    } else if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        if(GetTxPayload(tx, proTx)) {
            mapProTxRefs.emplace(proTx.proTxHash, tx_hash);
        }
    } else if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        if(GetTxPayload(tx, proTx)) {
            mapProTxRefs.emplace(proTx.proTxHash, tx_hash);
        }
    }

    TRACE3(mempool, added,
        entry.GetTx().GetHash().data(),
        entry.GetTxSize(),
        entry.GetFee()
    );
    return true;
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    // We increment mempool sequence value no matter removal reason
    // even if not directly reported below.
    uint64_t mempool_sequence = GetAndIncrementSequence();

    if (reason != MemPoolRemovalReason::BLOCK) {
        // Notify clients that a transaction has been removed from the mempool
        // for any reason except being included in a block. Clients interested
        // in transactions included in blocks can subscribe to the BlockConnected
        // notification.
        GetMainSignals().TransactionRemovedFromMempool(it->GetSharedTx(), reason, mempool_sequence);
    }
    TRACE5(mempool, removed,
        it->GetTx().GetHash().data(),
        RemovalReasonToString(reason).c_str(),
        it->GetTxSize(),
        it->GetFee(),
        std::chrono::duration_cast<std::chrono::duration<std::uint64_t>>(it->GetTime()).count()
    );

    const uint256 hash = it->GetTx().GetHash();
    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);
        

    RemoveUnbroadcastTx(hash, true /* add logging because unchecked */ );

    if (vTxHashes.size() > 1) {
        vTxHashes[it->vTxHashesIdx] = std::move(vTxHashes.back());
        vTxHashes[it->vTxHashesIdx].second->vTxHashesIdx = it->vTxHashesIdx;
        vTxHashes.pop_back();
        if (vTxHashes.size() * 2 < vTxHashes.capacity())
            vTxHashes.shrink_to_fit();
    } else
        vTxHashes.clear();

    totalTxSize -= it->GetTxSize();
    m_total_fee -= it->GetFee();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    // SYSCOIN deal with pro tx stuff first
    auto eraseProTxRef = [&](const uint256& proTxHash, const uint256& txHash) {
        LOCK2(cs_main, cs);
        auto its = mapProTxRefs.equal_range(proTxHash);
        for (auto it = its.first; it != its.second;) {
            if (it->second == txHash) {
                it = mapProTxRefs.erase(it);
            } else {
                ++it;
            }
        }
    };
    auto erasePQOperatorUpdate = [&](const uint256& proTxHash,
                                     const uint256& txHash) {
        const auto update{mapPQOperatorUpdates.find(proTxHash)};
        if (update != mapPQOperatorUpdates.end() && update->second == txHash) {
            mapPQOperatorUpdates.erase(update);
        }
    };
    const auto eraseExact = [&](auto& index, const auto& key,
                                const uint256& txHash) {
        const auto position{index.find(key)};
        if (position != index.end() && position->second == txHash) {
            index.erase(position);
        }
    };
    const uint256 tx_hash{it->GetTx().GetHash()};
    const auto global_reservation{mapPQGlobalReservations.find(tx_hash)};
    if (global_reservation != mapPQGlobalReservations.end()) {
        const auto key{mapPQGlobalKeys.find(
            global_reservation->second.public_key)};
        if (key != mapPQGlobalKeys.end() && key->second == tx_hash) {
            mapPQGlobalKeys.erase(key);
        }
        if (global_reservation->second.introduces_operator) {
            Assume(m_pq_operator_introductions != 0);
            if (m_pq_operator_introductions != 0) {
                --m_pq_operator_introductions;
            }
        }
        mapPQGlobalReservations.erase(global_reservation);
    }
    if (const auto operator_hash{GetPQOperatorUpdate(it->GetTx())}) {
        erasePQOperatorUpdate(*operator_hash, tx_hash);
        const auto reverse{mapPQUpdateCollateralByTx.find(tx_hash)};
        if (reverse != mapPQUpdateCollateralByTx.end()) {
            const auto collateral{
                mapPQUpdateCollaterals.find(reverse->second)};
            if (collateral != mapPQUpdateCollaterals.end() &&
                collateral->second == tx_hash) {
                mapPQUpdateCollaterals.erase(collateral);
            }
            mapPQUpdateCollateralByTx.erase(reverse);
        }
        if (it->GetTx().nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
            const auto revoke{mapPQRevocations.find(*operator_hash)};
            if (revoke != mapPQRevocations.end() && revoke->second == tx_hash) {
                mapPQRevocations.erase(revoke);
            }
        }
        if (IsStandalonePQRegistryTx(it->GetTx())) {
            eraseProTxRef(*operator_hash, tx_hash);
        }
    }
    if (it->GetTx().nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
        CProRegTx proTx;
        if (GetTxPayload(it->GetTx(), proTx)) {
            if (!proTx.collateralOutpoint.IsNull()) {
                eraseProTxRef(tx_hash, proTx.collateralOutpoint.hash);
            }
            eraseExact(mapProTxAddresses, proTx.addr, tx_hash);
            eraseExact(mapProTxPubKeyIDs, proTx.keyIDOwner, tx_hash);
            eraseExact(mapProTxCollaterals, proTx.collateralOutpoint,
                       tx_hash);
            eraseExact(mapProTxCollaterals,
                       COutPoint(tx_hash, proTx.collateralOutpoint.n),
                       tx_hash);
        }
    } else if (it->GetTx().nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if (GetTxPayload(it->GetTx(), proTx)) {
            eraseProTxRef(proTx.proTxHash, tx_hash);
            eraseExact(mapProTxAddresses, proTx.addr, tx_hash);
            if(!proTx.vchNEVMAddress.empty()) {
                eraseExact(mapProTxNEVMAddresses, proTx.vchNEVMAddress,
                           tx_hash);
            }
        }
    } else if (it->GetTx().nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR) {
        CProUpRegTx proTx;
        if (GetTxPayload(it->GetTx(), proTx)) { 
            eraseProTxRef(proTx.proTxHash, tx_hash);
        }
    } else if (it->GetTx().nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        CProUpRevTx proTx;
        if (GetTxPayload(it->GetTx(), proTx)) {
            eraseProTxRef(proTx.proTxHash, tx_hash);
        }
    }
    // remove nevm tx from mempool structure
    if(IsSyscoinMintTx(it->GetTx().nVersion)) {
        CMintSyscoin mintSyscoin(it->GetTx());
        if(!mintSyscoin.IsNull())
            setMintTxsMempool.erase(mintSyscoin.nTxHash);
    }
    // Remove only mempool-owned PoDA data on expiry/trim; confirmed and duplicate blobs are chain-owned.
    else if(it->GetTx().IsNEVMData() && (reason == MemPoolRemovalReason::EXPIRY || reason == MemPoolRemovalReason::SIZELIMIT)) {
        CNEVMData nevmData(it->GetTx());
        if(!nevmData.IsNull()){
            EraseMempoolNEVMData(nevmData.vchVersionHash, tx_hash);
        }
    }
    cachedInnerUsage -= memusage::DynamicUsage(it->GetMemPoolParentsConst()) + memusage::DynamicUsage(it->GetMemPoolChildrenConst());
    mapTx.erase(it);
    nTransactionsUpdated++;
    if (minerPolicyEstimator) {minerPolicyEstimator->removeTx(hash, false);}
}

// Calculates descendants of entry that are not already in setDescendants, and adds to
// setDescendants. Assumes entryit is already a tx in the mempool and CTxMemPoolEntry::m_children
// is correct for tx and all descendants.
// Also assumes that if an entry is in setDescendants already, then all
// in-mempool descendants of it are already in setDescendants as well, so that we
// can save time by not iterating over those entries.
void CTxMemPool::CalculateDescendants(txiter entryit, setEntries& setDescendants) const
{
    setEntries stage;
    if (setDescendants.count(entryit) == 0) {
        stage.insert(entryit);
    }
    // Traverse down the children of entry, only adding children that are not
    // accounted for in setDescendants already (because those children have either
    // already been walked, or will be walked in this iteration).
    while (!stage.empty()) {
        txiter it = *stage.begin();
        setDescendants.insert(it);
        stage.erase(it);

        const CTxMemPoolEntry::Children& children = it->GetMemPoolChildrenConst();
        for (const CTxMemPoolEntry& child : children) {
            txiter childiter = mapTx.iterator_to(child);
            if (!setDescendants.count(childiter)) {
                stage.insert(childiter);
            }
        }
    }
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    AssertLockHeld(cs);
        setEntries txToRemove;
        txiter origit = mapTx.find(origTx.GetHash());
        if (origit != mapTx.end()) {
            txToRemove.insert(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = mapTx.find(it->second->GetHash());
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
        }
        setEntries setAllRemoves;
        for (txiter it : txToRemove) {
            CalculateDescendants(it, setAllRemoves);
        }

        RemoveStaged(setAllRemoves, false, reason);
}

void CTxMemPool::removeForReorg(CChain& chain, std::function<bool(txiter)> check_final_and_mature)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    AssertLockHeld(cs);
    AssertLockHeld(::cs_main);

    setEntries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        if (check_final_and_mature(it)) txToRemove.insert(it);
    }
    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }
    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        assert(TestLockPointValidity(chain, it->GetLockPoints()));
    }
}
// SYSCOIN
bool CTxMemPool::existsConflicts(const CTransaction &tx) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        if(mapAssetAllocationConflicts.find(txin.prevout) != mapAssetAllocationConflicts.end())
            return true;
    }
    return false;
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second;
            if (txConflict != tx)
            {
                if (txConflict.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
                    // Remove all other protxes which refer to this protx
                    // NOTE: Can't use equal_range here as every call to removeRecursive might invalidate iterators
                    while (true) {
                        auto itPro = mapProTxRefs.find(txConflict.GetHash());
                        if (itPro == mapProTxRefs.end()) {
                            break;
                        }
                        auto txit = mapTx.find(itPro->second);
                        if (txit != mapTx.end()) {
                            ClearPrioritisation(txit->GetTx().GetHash());
                            removeRecursive(txit->GetTx(), MemPoolRemovalReason::CONFLICT);
                        } else {
                            mapProTxRefs.erase(itPro);
                        }
                    }
                }
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
            
        }
    }
}
void CTxMemPool::removeProTxNEVMKeyConflicts(const CTransaction &tx, const std::vector<unsigned char> &vchNEVMAddress)
{
    if (!vchNEVMAddress.empty() && mapProTxNEVMAddresses.count(vchNEVMAddress)) {
        uint256 conflictHash = mapProTxNEVMAddresses[vchNEVMAddress];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

// SYSCOIN
void CTxMemPool::removeZDAGConflicts(const CTransaction &tx)
{
    // Remove conflicting zdag transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapAssetAllocationConflicts.find(txin.prevout);
        // remove the two transactions linked to this prevout in event of a conflict
        if (it != mapAssetAllocationConflicts.end()) {
            if(it->second.first) {
                ClearPrioritisation(it->second.first->GetHash());
                removeRecursive(*it->second.first, MemPoolRemovalReason::CONFLICT);
            }
            if(it->second.second) {
                ClearPrioritisation(it->second.second->GetHash());
                removeRecursive(*it->second.second, MemPoolRemovalReason::CONFLICT);
            }
        } 
    }
}

// true if other tx (conflicting) was first in mempool and it was involved in asset double spend
bool CTxMemPool::isSyscoinConflictIsFirstSeen(const CTransaction &tx) const {
    AssertLockHeld(cs);
    if(mapAssetAllocationConflicts.empty())
        return true;
    for (const CTxIn &txin : tx.vin) {
        auto it = mapAssetAllocationConflicts.find(txin.prevout);
        // ensure that we check for mapAssetAllocationConflicts intersection of this input
        // the only time conflicts are allowed and would cause problems for zdag is when its double spent without RBF
        // we allow one double spend input to be propagated and here we ensure we are only dealing with skipping transactions based on time
        // if it is one of those transactions that propagated double spent input related to syscoin asset tx
        if (it != mapAssetAllocationConflicts.end()) {
            txiter thisit, conflictit;
            txiter firstit = mapTx.find(it->second.first->GetHash());
            thisit = mapTx.end();
            if(firstit != mapTx.end()){
                if(firstit->GetTx() == tx)
                    thisit = firstit;
            }
            txiter secondit = mapTx.find(it->second.second->GetHash());
            if(secondit != mapTx.end()){
                if(secondit->GetTx() == tx) {
                    thisit = secondit;
                    conflictit = firstit;
                } else {
                    conflictit = secondit;
                }
            }
            // if for some reason thisit is not found (it should be) we just return false
            if(thisit == mapTx.end()) {
                return false;
            }
            // if first tx found not second, true if first one is tx, otherwise false
            if (firstit != mapTx.end() && secondit == mapTx.end()) {
                return firstit == thisit;
            // if second tx found not first, true if second one is tx, otherwise false
            } else if (secondit != mapTx.end() && firstit == mapTx.end()) {
                return secondit == thisit;
            // if first tx and second tx are not in mempool
            } else if(firstit == mapTx.end() && secondit == mapTx.end())
                return false;


            // if transaction in question was signalling RBF but conflicting transaction was not
            // prefer the conflict version over this one as prescedence over time based ordering
            // if both signal RBF, just choose the first one in mempool based on time below (they wouldn't have been used for point-of-sale anyway due to RBF)
            const bool thisRBF = SignalsOptInRBF(thisit->GetTx());
            const bool otherRBF = SignalsOptInRBF(conflictit->GetTx());
            if(thisRBF && !otherRBF) {
                return false;
            // if this transaction is non-RBF but conflict signals it, prefer this one regardless of time order
            } else if(!thisRBF && otherRBF) {
                return true;
            }
            // if conflicting transaction was received before the transaction in question
            // idea is to mine the oldest transaction in event of conflict
            // upon block, the conflict is removed
            const auto time1 = conflictit->GetTime();
            const auto time2 = thisit->GetTime();
            if(time1 < time2){
                return false;
            } else if(time1 == time2) {
                return thisit->GetTx().GetHash() < conflictit->GetTx().GetHash();
            }
        }
    }
    return true;
}

void CTxMemPool::removeProTxPubKeyConflicts(const CTransaction &tx, const CKeyID &keyId)
{
    if (mapProTxPubKeyIDs.count(keyId)) {
        uint256 conflictHash = mapProTxPubKeyIDs[keyId];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

void CTxMemPool::removeProTxCollateralConflicts(const CTransaction &tx, const COutPoint &collateralOutpoint)
{
    if (mapProTxCollaterals.count(collateralOutpoint)) {
        uint256 conflictHash = mapProTxCollaterals[collateralOutpoint];
        if (conflictHash != tx.GetHash() && mapTx.count(conflictHash)) {
            removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}

void CTxMemPool::removeProTxSpentCollateralConflicts(const CTransaction &tx)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    const CDeterministicMNList mn_list{
        deterministicMNManager
            ? deterministicMNManager->GetListAtChainTip()
            : CDeterministicMNList{}};
    removeProTxSpentCollateralConflicts(tx, mn_list);
}

void CTxMemPool::removeProTxSpentCollateralConflicts(
    const CTransaction& tx,
    const CDeterministicMNList& mn_list)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    // Remove TXs that refer to a MN for which the collateral was spent
    auto removeSpentCollateralConflict = [&](const uint256& proTxHash) {
        LOCK2(cs_main, cs);
        // Can't use equal_range here as every call to removeRecursive might invalidate iterators
        while (true) {
            auto it = mapProTxRefs.find(proTxHash);
            if (it == mapProTxRefs.end()) {
                break;
            }
            auto conflictIt = mapTx.find(it->second);
            if (conflictIt != mapTx.end()) {
                removeRecursive(conflictIt->GetTx(), MemPoolRemovalReason::CONFLICT);
            } else {
                // Should not happen as we track referencing TXs in addUnchecked/removeUnchecked.
                // But lets be on the safe side and not run into an endless loop...
                LogPrint(BCLog::MEMPOOL, "%s: ERROR: found invalid TX ref in mapProTxRefs, proTxHash=%s, txHash=%s\n", __func__, proTxHash.ToString(), it->second.ToString());
                mapProTxRefs.erase(it);
            }
        }
    };
    for (const auto& in : tx.vin) {
        auto collateralIt = mapProTxCollaterals.find(in.prevout);
        if (collateralIt != mapProTxCollaterals.end()) {
            // These are not yet mined ProRegTxs
            const uint256 pro_reg_txid{collateralIt->second};
            const auto pending_registration{mapTx.find(pro_reg_txid)};
            if (pending_registration != mapTx.end()) {
                removeRecursive(pending_registration->GetTx(),
                                MemPoolRemovalReason::CONFLICT);
            } else {
                mapProTxCollaterals.erase(collateralIt);
            }
        }
        auto dmn = mn_list.GetMNByCollateral(in.prevout);
        if (dmn) {
            // These are updates referring to a mined ProRegTx
            removeSpentCollateralConflict(dmn->proTxHash);
        }
    }
}

void CTxMemPool::removeProTxConflicts(const CTransaction &tx)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    const CDeterministicMNList mn_list{
        deterministicMNManager
            ? deterministicMNManager->GetListAtChainTip()
            : CDeterministicMNList{}};
    removeProTxConflicts(tx, mn_list);
}

void CTxMemPool::removeProTxConflicts(
    const CTransaction& tx,
    const CDeterministicMNList& mn_list)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    removeProTxSpentCollateralConflicts(tx, mn_list);
    const uint256 tx_hash{tx.GetHash()};

    // A connected block can contain a conflicting provider mutation that was
    // never in this mempool. Copy ids before recursive removal mutates indexes.
    std::set<uint256> pq_conflicts;
    const auto global_payload{GetPQGlobalKeyPayload(tx)};
    const auto pq_operator_update{GetPQOperatorUpdate(tx)};
    const auto provider_mutation{GetProviderMutation(tx)};
    if (global_payload) {
        const auto key{
            mapPQGlobalKeys.find(global_payload->candidate.public_key)};
        if (key != mapPQGlobalKeys.end() && key->second != tx_hash) {
            pq_conflicts.emplace(key->second);
        }
        const auto refs{
            mapProTxRefs.equal_range(global_payload->pro_tx_hash)};
        for (auto ref = refs.first; ref != refs.second; ++ref) {
            if (ref->second != tx_hash) pq_conflicts.emplace(ref->second);
        }
    }
    if (pq_operator_update) {
        const auto update{mapPQOperatorUpdates.find(*pq_operator_update)};
        if (update != mapPQOperatorUpdates.end() && update->second != tx_hash) {
            pq_conflicts.emplace(update->second);
        }
        const auto dmn{mn_list.GetMN(*pq_operator_update)};
        if (dmn) {
            const auto replacement{
                mapProTxCollaterals.find(dmn->collateralOutpoint)};
            if (replacement != mapProTxCollaterals.end() &&
                replacement->second != tx_hash) {
                pq_conflicts.emplace(replacement->second);
            }
        }
    }
    if (provider_mutation) {
        const auto revoke{mapPQRevocations.find(*provider_mutation)};
        if (revoke != mapPQRevocations.end() && revoke->second != tx_hash) {
            pq_conflicts.emplace(revoke->second);
        }
    }
    const bool is_pq_revoke =
        tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE &&
        pq_operator_update.has_value();
    if (is_pq_revoke) {
        const auto refs{mapProTxRefs.equal_range(*pq_operator_update)};
        for (auto ref = refs.first; ref != refs.second; ++ref) {
            if (ref->second != tx_hash) pq_conflicts.emplace(ref->second);
        }
    }
    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
        CProRegTx registration;
        if (GetTxPayload(tx, registration) &&
            !registration.collateralOutpoint.hash.IsNull()) {
            const auto replaced{
                mn_list.GetMNByCollateral(registration.collateralOutpoint)};
            if (replaced) {
                const auto refs{
                    mapProTxRefs.equal_range(replaced->proTxHash)};
                for (auto ref = refs.first; ref != refs.second; ++ref) {
                    if (ref->second != tx_hash) {
                        pq_conflicts.emplace(ref->second);
                    }
                }
            }
        }
    }
    for (const auto& conflict_hash : pq_conflicts) {
        const auto conflict{mapTx.find(conflict_hash)};
        if (conflict != mapTx.end()) {
            removeRecursive(conflict->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }

    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
        CProRegTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrint(BCLog::MEMPOOL, "%s: ERROR: Invalid transaction payload, tx: %s\n", __func__, tx_hash.ToString());
            return;
        }

        if (mapProTxAddresses.count(proTx.addr)) {
            uint256 conflictHash = mapProTxAddresses[proTx.addr];
            if (conflictHash != tx_hash && mapTx.count(conflictHash)) {
                removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
            }
        }
        removeProTxPubKeyConflicts(tx, proTx.keyIDOwner);
        if (!proTx.collateralOutpoint.hash.IsNull()) {
            removeProTxCollateralConflicts(tx, proTx.collateralOutpoint);
        } else {
            removeProTxCollateralConflicts(tx, COutPoint(tx_hash, proTx.collateralOutpoint.n));
        }
    } else if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        CProUpServTx proTx;
        if (!GetTxPayload(tx, proTx)) {
            LogPrint(BCLog::MEMPOOL, "%s: ERROR: Invalid transaction payload, tx: %s\n", __func__, tx_hash.ToString());
            return;
        }

        if (mapProTxAddresses.count(proTx.addr)) {
            uint256 conflictHash = mapProTxAddresses[proTx.addr];
            if (conflictHash != tx_hash && mapTx.count(conflictHash)) {
                removeRecursive(mapTx.find(conflictHash)->GetTx(), MemPoolRemovalReason::CONFLICT);
            }
        }
        removeProTxNEVMKeyConflicts(tx, proTx.vchNEVMAddress);
    }
}

// SYSCOIN BEGIN: Indexed package-local provider and PQ conflict validation.
std::optional<size_t> CTxMemPool::FindPackageProviderTxConflict(
    const std::vector<CTransactionRef>& package,
    const CBlockIndex* active_tip) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    m_last_package_provider_conflict_stats = {};

    std::optional<size_t> first_branch_bound;
    for (size_t index{0}; index < package.size(); ++index) {
        if (package[index] &&
            IsBranchBoundProviderTransaction(*package[index])) {
            first_branch_bound = index;
            break;
        }
    }
    if (!first_branch_bound) {
        // Per-transaction PreChecks already used the indexed ordinary path.
        return std::nullopt;
    }
    if (package.size() > MAX_PROVIDER_PACKAGE_TRANSACTIONS) {
        return first_branch_bound;
    }

    std::set<uint256> requested_operators;
    std::optional<size_t> first_global;
    for (size_t index{0}; index < package.size(); ++index) {
        if (!package[index] ||
            package[index]->nVersion != SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY) {
            continue;
        }
        if (!first_global) first_global = index;
        const auto payload{GetPQGlobalKeyPayload(*package[index])};
        if (!payload) return index;
        requested_operators.insert(payload->pro_tx_hash);
    }
    m_last_package_provider_conflict_stats.registry_operator_requests =
        requested_operators.size();

    llmq::pq::PQRegistryMempoolView view;
    if (first_global) {
        if (active_tip == nullptr || !deterministicMNManager ||
            requested_operators.size() >
                MAX_PROVIDER_PACKAGE_TRANSACTIONS) {
            return first_global;
        }
        std::vector<uint256> requested{requested_operators.begin(),
                                       requested_operators.end()};
        std::string error;
        if (!deterministicMNManager->GetPQRegistryMempoolView(
                active_tip, requested, view, error)) {
            LogPrint(BCLog::MEMPOOL,
                     "%s: failed to load PQ reservation view: %s\n",
                     __func__, error);
            return first_global;
        }
    }
    return FindPackageProviderTxConflict(package, active_tip, view);
}

std::optional<size_t> CTxMemPool::FindPackageProviderTxConflict(
    const std::vector<CTransactionRef>& package,
    const CBlockIndex* active_tip,
    const llmq::pq::PQRegistryMempoolView& registry_view) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    m_last_package_provider_conflict_stats
        .indexed_provider_references_examined = 0;

    CDeterministicMNList mn_list;
    if (active_tip != nullptr && deterministicMNManager) {
        try {
            mn_list = deterministicMNManager->GetListForBlock(active_tip);
        } catch (const std::exception&) {
            for (size_t index{0}; index < package.size(); ++index) {
                if (package[index] &&
                    (GetPQOperatorUpdate(*package[index]) ||
                     GetProviderMutation(*package[index]) ||
                     package[index]->nVersion ==
                         SYSCOIN_TX_VERSION_MN_REGISTER)) {
                    return index;
                }
            }
        }
    }
    return FindPackageProviderTxConflict(package, mn_list, registry_view);
}

std::optional<size_t> CTxMemPool::FindPackageProviderTxConflict(
    const std::vector<CTransactionRef>& package,
    const CDeterministicMNList& mn_list,
    const llmq::pq::PQRegistryMempoolView& registry_view) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);

    if (package.size() > MAX_PROVIDER_PACKAGE_TRANSACTIONS) {
        for (size_t index{0}; index < package.size(); ++index) {
            if (package[index] &&
                IsBranchBoundProviderTransaction(*package[index])) {
                return index;
            }
        }
        return std::nullopt;
    }

    // Only package-local reservations need materialization. Existing mempool
    // reservations remain stable under cs and are queried by their indexes.
    std::set<uint256> package_pq_operator_updates;
    std::set<uint256> package_provider_references;
    std::map<uint256, std::set<uint256>>
        package_provider_reference_txids;
    std::set<uint256> package_pq_revocations;
    std::set<std::array<uint8_t, 32>> package_global_keys;
    std::set<CService> package_provider_addresses;
    std::set<std::vector<unsigned char>> package_provider_nevm_addresses;
    std::set<CKeyID> package_provider_owner_keys;
    std::set<COutPoint> package_provider_collaterals;
    std::set<COutPoint> spent_inputs;
    std::map<uint256, const CTransaction*> prior_package_transactions;

    const auto has_pq_operator_update = [&](const uint256& pro_tx_hash) {
        return package_pq_operator_updates.count(pro_tx_hash) != 0 ||
               mapPQOperatorUpdates.count(pro_tx_hash) != 0;
    };
    const auto has_provider_reference = [&](const uint256& pro_tx_hash) {
        return package_provider_references.count(pro_tx_hash) != 0 ||
               mapProTxRefs.count(pro_tx_hash) != 0;
    };
    const auto has_pq_revocation = [&](const uint256& pro_tx_hash) {
        return package_pq_revocations.count(pro_tx_hash) != 0 ||
               mapPQRevocations.count(pro_tx_hash) != 0;
    };
    const auto has_provider_collateral = [&](const COutPoint& collateral) {
        return package_provider_collaterals.count(collateral) != 0 ||
               mapProTxCollaterals.count(collateral) != 0;
    };

    const auto collect_ancestor_txids =
        [&](const CTransaction& descendant)
            EXCLUSIVE_LOCKS_REQUIRED(cs) {
            std::vector<uint256> pending;
            pending.reserve(descendant.vin.size());
            for (const auto& input : descendant.vin) {
                pending.push_back(input.prevout.hash);
            }
            std::set<uint256> visited;
            while (!pending.empty()) {
                const uint256 txid{pending.back()};
                pending.pop_back();
                if (!visited.insert(txid).second) continue;

                const CTransaction* parent{nullptr};
                const auto package_parent{
                    prior_package_transactions.find(txid)};
                if (package_parent != prior_package_transactions.end()) {
                    parent = package_parent->second;
                } else {
                    const auto mempool_parent{mapTx.find(txid)};
                    if (mempool_parent != mapTx.end()) {
                        parent = &mempool_parent->GetTx();
                    }
                }
                if (parent == nullptr) continue;
                for (const auto& input : parent->vin) {
                    pending.push_back(input.prevout.hash);
                }
            }
            return visited;
        };

    const auto has_unordered_provider_reference =
        [&](const uint256& pro_tx_hash, const CTransaction& replacement)
            EXCLUSIVE_LOCKS_REQUIRED(cs) {
            std::optional<std::set<uint256>> ancestors;
            const auto is_not_ancestor = [&](const uint256& txid)
                EXCLUSIVE_LOCKS_REQUIRED(cs) {
                if (!ancestors) {
                    ancestors.emplace(
                        collect_ancestor_txids(replacement));
                }
                return ancestors->count(txid) == 0;
            };

            const auto package_refs{
                package_provider_reference_txids.find(pro_tx_hash)};
            if (package_refs != package_provider_reference_txids.end()) {
                for (const auto& txid : package_refs->second) {
                    if (is_not_ancestor(txid)) return true;
                }
            }
            const auto [first, last]{mapProTxRefs.equal_range(pro_tx_hash)};
            for (auto reference{first}; reference != last; ++reference) {
                ++m_last_package_provider_conflict_stats
                      .indexed_provider_references_examined;
                if (mapTx.find(reference->second) != mapTx.end() &&
                    is_not_ancestor(reference->second)) {
                    return true;
                }
            }
            return false;
        };

    size_t package_operator_introductions{0};
    for (size_t index{0}; index < package.size(); ++index) {
        if (!package[index]) continue;
        const CTransaction& tx{*package[index]};
        const auto global{GetPQGlobalKeyPayload(tx)};
        if (tx.nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY && !global) {
            return index;
        }
        const auto pq_operator_update{GetPQOperatorUpdate(tx)};
        const auto provider_mutation{GetProviderMutation(tx)};
        const bool is_pq_revoke{
            tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE &&
            pq_operator_update.has_value()};

        // Registry updates require the target DMN to survive the complete
        // block. Ordinary provider mutations may precede a collateral spend,
        // but tx86/revoke cannot coexist with one in either transaction order.
        for (const auto& input : tx.vin) {
            const auto dmn{mn_list.GetMNByCollateral(input.prevout)};
            if (dmn && has_pq_operator_update(dmn->proTxHash)) {
                return index;
            }
        }
        if (pq_operator_update) {
            const auto dmn{mn_list.GetMN(*pq_operator_update)};
            if (dmn &&
                (SpendsOutpoint(tx, dmn->collateralOutpoint) ||
                 spent_inputs.count(dmn->collateralOutpoint) != 0 ||
                 mapNextTx.count(dmn->collateralOutpoint) != 0 ||
                 has_provider_collateral(dmn->collateralOutpoint))) {
                return index;
            }
        }
        if (provider_mutation) {
            const auto dmn{mn_list.GetMN(*provider_mutation)};
            if (dmn &&
                has_provider_collateral(dmn->collateralOutpoint)) {
                // An ordinary mutation followed by the replacement can be
                // consensus-valid, but independent mempool transactions have
                // no ordering guarantee. Excluding both orders keeps every
                // template valid without fee-dependent provider semantics.
                return index;
            }
        }

        if (pq_operator_update) {
            if (package_pq_operator_updates.count(*pq_operator_update) != 0 ||
                mapPQOperatorUpdates.count(*pq_operator_update) != 0) {
                return index;
            }
            package_pq_operator_updates.insert(*pq_operator_update);
        }
        if (provider_mutation &&
            has_pq_revocation(*provider_mutation)) {
            return index;
        }
        if (is_pq_revoke &&
            has_provider_reference(*pq_operator_update)) {
            return index;
        }

        if (global) {
            if (package_global_keys.count(global->candidate.public_key) != 0 ||
                mapPQGlobalKeys.count(global->candidate.public_key) != 0) {
                return index;
            }
            package_global_keys.insert(global->candidate.public_key);
            const auto* current{
                registry_view.FindOperator(global->pro_tx_hash)};
            if (current == nullptr) return index;
            const bool introduces_operator{current->state_exists == 0};
            const size_t next_operator_introductions{
                package_operator_introductions +
                (introduces_operator ? 1U : 0U)};
            if (!HasPQRegistryCapacity(
                    registry_view.operator_state_count,
                    m_pq_operator_introductions,
                    next_operator_introductions,
                    llmq::pq::MAX_PQ_OPERATOR_STATES)) {
                return index;
            }
            package_operator_introductions = next_operator_introductions;
        }

        if (tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
            CProRegTx payload;
            if (!GetTxPayload(tx, payload)) return index;
            if (package_provider_addresses.count(payload.addr) != 0 ||
                mapProTxAddresses.count(payload.addr) != 0 ||
                package_provider_owner_keys.count(payload.keyIDOwner) != 0 ||
                mapProTxPubKeyIDs.count(payload.keyIDOwner) != 0) {
                return index;
            }
            package_provider_addresses.insert(payload.addr);
            package_provider_owner_keys.insert(payload.keyIDOwner);

            COutPoint collateral{payload.collateralOutpoint};
            if (collateral.hash.IsNull()) {
                collateral.hash = tx.GetHash();
            } else {
                if (spent_inputs.count(collateral) != 0 ||
                    mapNextTx.count(collateral) != 0) {
                    return index;
                }
                const auto replaced{mn_list.GetMNByCollateral(collateral)};
                if (replaced) {
                    if (has_pq_operator_update(replaced->proTxHash)) {
                        return index;
                    }
                    if (has_unordered_provider_reference(
                            replaced->proTxHash, tx)) {
                        // Ordinary mutations may precede a replacement only
                        // when UTXO ancestry forces that consensus-valid order.
                        return index;
                    }
                }
            }
            if (has_provider_collateral(collateral)) {
                return index;
            }
            package_provider_collaterals.insert(collateral);
            if (!payload.collateralOutpoint.hash.IsNull()) {
                package_provider_references.insert(tx.GetHash());
            }
        } else if (tx.nVersion ==
                   SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
            CProUpServTx payload;
            if (!GetTxPayload(tx, payload)) return index;
            if (payload.addr != CService() &&
                (package_provider_addresses.count(payload.addr) != 0 ||
                 mapProTxAddresses.count(payload.addr) != 0)) {
                return index;
            }
            package_provider_addresses.insert(payload.addr);
            if (!payload.vchNEVMAddress.empty() &&
                (package_provider_nevm_addresses.count(
                     payload.vchNEVMAddress) != 0 ||
                 mapProTxNEVMAddresses.count(payload.vchNEVMAddress) != 0)) {
                return index;
            }
            if (!payload.vchNEVMAddress.empty()) {
                package_provider_nevm_addresses.insert(
                    payload.vchNEVMAddress);
            }
        }

        if (provider_mutation) {
            package_provider_references.insert(*provider_mutation);
            package_provider_reference_txids[*provider_mutation].insert(
                tx.GetHash());
        } else if (global) {
            package_provider_references.insert(global->pro_tx_hash);
            package_provider_reference_txids[global->pro_tx_hash].insert(
                tx.GetHash());
        }
        if (is_pq_revoke) {
            package_pq_revocations.insert(*pq_operator_update);
        }
        for (const auto& input : tx.vin) {
            spent_inputs.insert(input.prevout);
        }
        prior_package_transactions.emplace(tx.GetHash(), &tx);
    }
    return std::nullopt;
}
// SYSCOIN END: Indexed package-local provider and PQ conflict validation.

bool CTxMemPool::RebuildPQRegistryReservations(
    const CBlockIndex* active_tip)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);

    if (mapPQGlobalReservations.empty()) {
        m_pq_operator_introductions = 0;
        return true;
    }

    std::set<uint256> requested_set;
    for (const auto& [_, reservation] : mapPQGlobalReservations) {
        requested_set.insert(reservation.pro_tx_hash);
    }
    llmq::pq::PQRegistryMempoolView view;
    std::string error;
    const bool loaded{
        active_tip != nullptr && deterministicMNManager &&
        requested_set.size() <=
            llmq::pq::MAX_PQ_MEMPOOL_OPERATOR_REQUESTS &&
        deterministicMNManager->GetPQRegistryMempoolView(
            active_tip,
            std::vector<uint256>{requested_set.begin(), requested_set.end()},
            view, error)};
    if (!loaded) {
        LogPrint(BCLog::MEMPOOL,
                 "%s: dropping PQ reservations after view failure: %s\n",
                 __func__, error);
        std::vector<uint256> txids;
        txids.reserve(mapPQGlobalReservations.size());
        for (const auto& [txid, _] : mapPQGlobalReservations) {
            txids.push_back(txid);
        }
        for (const auto& txid : txids) {
            const auto entry{mapTx.find(txid)};
            if (entry != mapTx.end()) {
                removeRecursive(entry->GetTx(),
                                MemPoolRemovalReason::REORG);
            }
        }
        return false;
    }

    return RebuildPQRegistryReservations(view);
}

bool CTxMemPool::RebuildPQRegistryReservations(
    const llmq::pq::PQRegistryMempoolView& view)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);

    std::vector<uint256> aged;
    for (const auto& [txid, reservation] : mapPQGlobalReservations) {
        const auto* current{view.FindOperator(reservation.pro_tx_hash)};
        bool same_commitment{false};
        if (current != nullptr && current->has_global_key != 0) {
            const auto& candidate{reservation.commitment};
            const auto& existing{current->current_commitment};
            same_commitment =
                candidate.version == existing.version &&
                candidate.profile == existing.profile &&
                candidate.usage_cap == existing.usage_cap &&
                candidate.depth == existing.depth &&
                candidate.generation == existing.generation &&
                candidate.first_epoch == existing.first_epoch &&
                candidate.tree_id == existing.tree_id &&
                candidate.root == existing.root;
        }
        llmq::pq::ChildKeyTreeCommitment candidate;
        candidate.version = reservation.commitment.version;
        candidate.profile = reservation.commitment.profile;
        candidate.usage_cap = reservation.commitment.usage_cap;
        candidate.depth = reservation.commitment.depth;
        candidate.generation = reservation.commitment.generation;
        candidate.first_epoch = reservation.commitment.first_epoch;
        candidate.tree_id = reservation.commitment.tree_id;
        candidate.root = reservation.commitment.root;
        if (!same_commitment &&
            (view.has_next_block_schedule == 0 ||
             !candidate.IsStructurallyValid() ||
             candidate.first_epoch != view.next_first_mutable_epoch)) {
            aged.push_back(txid);
        }
    }
    for (const auto& txid : aged) {
        const auto entry{mapTx.find(txid)};
        if (entry != mapTx.end()) {
            removeRecursive(entry->GetTx(), MemPoolRemovalReason::REORG);
        }
    }

    m_pq_operator_introductions = 0;
    for (auto& [_, reservation] : mapPQGlobalReservations) {
        const auto* current{view.FindOperator(reservation.pro_tx_hash)};
        reservation.introduces_operator =
            current == nullptr || current->state_exists == 0;
        m_pq_operator_introductions +=
            reservation.introduces_operator ? 1 : 0;
    }

    struct OrderedReservation {
        std::chrono::seconds time;
        uint256 txid;
    };
    std::vector<OrderedReservation> ordered;
    ordered.reserve(mapPQGlobalReservations.size());
    for (const auto& [txid, _] : mapPQGlobalReservations) {
        const auto entry{mapTx.find(txid)};
        if (entry != mapTx.end()) {
            ordered.push_back({entry->GetTime(), txid});
        }
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const OrderedReservation& lhs,
                 const OrderedReservation& rhs) {
                  return lhs.time < rhs.time ||
                         (lhs.time == rhs.time && lhs.txid < rhs.txid);
              });

    const size_t available_operators{
        view.operator_state_count <= llmq::pq::MAX_PQ_OPERATOR_STATES
            ? llmq::pq::MAX_PQ_OPERATOR_STATES -
                  view.operator_state_count
            : 0};
    size_t retained_operators{0};
    std::vector<uint256> overflow;
    for (const auto& item : ordered) {
        const auto reservation{mapPQGlobalReservations.find(item.txid)};
        if (reservation == mapPQGlobalReservations.end()) continue;
        const bool operator_overflow{
            reservation->second.introduces_operator &&
            retained_operators >= available_operators};
        if (operator_overflow) {
            overflow.push_back(item.txid);
            continue;
        }
        retained_operators +=
            reservation->second.introduces_operator ? 1 : 0;
    }
    for (const auto& txid : overflow) {
        const auto entry{mapTx.find(txid)};
        if (entry != mapTx.end()) {
            removeRecursive(entry->GetTx(), MemPoolRemovalReason::REORG);
        }
    }
    return true;
}

void CTxMemPool::RemoveProviderTransactionsForReorg()
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);

    // Provider authorization and membership are parent-branch state. Reorgs
    // are rare, and dropping these entries avoids doing attacker-amplifiable
    // SLH verification while holding the chain and mempool locks. Valid
    // transactions can be relayed again against the new branch.
    std::vector<uint256> txids;
    for (const auto& entry : mapTx) {
        if (IsBranchBoundProviderTransaction(entry.GetTx())) {
            txids.push_back(entry.GetTx().GetHash());
        }
    }
    for (const auto& txid : txids) {
        const auto entry{mapTx.find(txid)};
        if (entry != mapTx.end()) {
            removeRecursive(entry->GetTx(), MemPoolRemovalReason::REORG);
        }
    }
}

// SYSCOIN BEGIN: Purge legacy provider payloads at the PQ activation boundary.
void CTxMemPool::RemoveLegacyProviderTransactionsForPQActivation()
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);

    // SYSCOIN: The mempool was populated for a legacy next block. At the
    // boundary all provider payloads admitted under that wire era become
    // invalid, while preparation-era global-key registrations remain valid.
    std::vector<uint256> txids;
    for (const auto& entry : mapTx) {
        const auto version{entry.GetTx().nVersion};
        if (version == SYSCOIN_TX_VERSION_MN_REGISTER ||
            version == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE ||
            version == SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR ||
            version == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
            txids.push_back(entry.GetTx().GetHash());
        }
    }
    for (const auto& txid : txids) {
        const auto entry{mapTx.find(txid)};
        if (entry != mapTx.end()) {
            removeRecursive(entry->GetTx(), MemPoolRemovalReason::CONFLICT);
        }
    }
}
// SYSCOIN END: Purge legacy provider payloads at the PQ activation boundary.
/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    std::vector<const CTxMemPoolEntry*> entries;
    for (const auto& tx : vtx)
    {
        uint256 hash = tx->GetHash();

        indexed_transaction_set::iterator i = mapTx.find(hash);
        if (i != mapTx.end())
            entries.push_back(&*i);
    }
    // Before the txs in the new block have been removed from the mempool, update policy estimates
    if (minerPolicyEstimator) {minerPolicyEstimator->processBlock(nBlockHeight, entries);}
    for (const auto& tx : vtx)
    {
        txiter it = mapTx.find(tx->GetHash());
        if (it != mapTx.end()) {
            setEntries stage;
            stage.insert(it);
            RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
        }
        removeConflicts(*tx);
        // SYSCOIN
        removeZDAGConflicts(*tx);
        removeProTxConflicts(*tx);
        ClearPrioritisation(tx->GetHash());
    }
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
}

void CTxMemPool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const
{
    if (m_check_ratio == 0) return;

    if (GetRand(m_check_ratio) >= 1) return;

    AssertLockHeld(::cs_main);
    LOCK(cs);
    LogPrint(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    CAmount check_total_fee{0};
    uint64_t innerUsage = 0;
    uint64_t prev_ancestor_count{0};

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(&active_coins_tip));

    for (const auto& it : GetSortedDepthAndScore()) {
        checkTotal += it->GetTxSize();
        check_total_fee += it->GetFee();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();
        innerUsage += memusage::DynamicUsage(it->GetMemPoolParentsConst()) + memusage::DynamicUsage(it->GetMemPoolChildrenConst());
        CTxMemPoolEntry::Parents setParentCheck;
        // SYSCOIN
        bool bFoundConflict = false;
        bool bAssetAllocationTX = IsAssetAllocationTx(tx.nVersion);
        for (const CTxIn &txin : tx.vin) {
            if(mapAssetAllocationConflicts.find(txin.prevout) != mapAssetAllocationConflicts.end()) {
                bFoundConflict = true;
                break;
            }
        }
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                setParentCheck.insert(*it2);
            }
            // SYSCOIN We are iterating through the mempool entries sorted in order by ancestor count.
            // All parents must have been checked before their children and their coins added to
            // the mempoolDuplicate coins cache.
            if(!bFoundConflict)
                assert(mempoolDuplicate.HaveCoin(txin.prevout));
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            // SYSCOIN
            if(bFoundConflict) {
                assert(*it3->first == txin.prevout);
                auto itzdagconflict = mapAssetAllocationConflicts.find(txin.prevout);
                // does dbl-spend conflict exist, we don't have enough info to check tx otherwise if no conflict
                if(itzdagconflict != mapAssetAllocationConflicts.end()) {
                    // the tx must be one of the dbl-spend conflicts
                    assert((itzdagconflict->second.first && *itzdagconflict->second.first == tx) || (itzdagconflict->second.second && *itzdagconflict->second.second == tx));
                }
            } else {
                assert(it3->first == &txin.prevout);
                assert(*it3->second == tx);          
            }
        }
        auto comp = [](const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) -> bool {
            return a.GetTx().GetHash() == b.GetTx().GetHash();
        };
        assert(setParentCheck.size() == it->GetMemPoolParentsConst().size());
        assert(std::equal(setParentCheck.begin(), setParentCheck.end(), it->GetMemPoolParentsConst().begin(), comp));
        // Verify ancestor state is correct.
        auto ancestors{AssumeCalculateMemPoolAncestors(__func__, *it, Limits::NoLimits())};
        uint64_t nCountCheck = ancestors.size() + 1;
        int32_t nSizeCheck = it->GetTxSize();
        CAmount nFeesCheck = it->GetModifiedFee();
        int64_t nSigOpCheck = it->GetSigOpCost();

        for (txiter ancestorIt : ancestors) {
            nSizeCheck += ancestorIt->GetTxSize();
            nFeesCheck += ancestorIt->GetModifiedFee();
            nSigOpCheck += ancestorIt->GetSigOpCost();
        }

        assert(it->GetCountWithAncestors() == nCountCheck);
        assert(it->GetSizeWithAncestors() == nSizeCheck);
        assert(it->GetSigOpCostWithAncestors() == nSigOpCheck);
        assert(it->GetModFeesWithAncestors() == nFeesCheck);
        // Sanity check: we are walking in ascending ancestor count order.
        assert(prev_ancestor_count <= it->GetCountWithAncestors());
        prev_ancestor_count = it->GetCountWithAncestors();

        // Check children against mapNextTx
        CTxMemPoolEntry::Children setChildrenCheck;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        int32_t child_sizes{0};
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = mapTx.find(iter->second->GetHash());
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            if (setChildrenCheck.insert(*childit).second) {
                child_sizes += childit->GetTxSize();
            }
        }
        if(!bAssetAllocationTX) {
            assert(setChildrenCheck.size() == it->GetMemPoolChildrenConst().size());
            assert(std::equal(setChildrenCheck.begin(), setChildrenCheck.end(), it->GetMemPoolChildrenConst().begin(), comp));
        }
            
        // Also check to make sure size is greater than sum with immediate children.
        // just a sanity check, not definitive that this calc is correct...
        assert(it->GetSizeWithDescendants() >= child_sizes + it->GetTxSize());

        TxValidationState dummy_state; // Not used. CheckTxInputs() should always pass
        CAmount txfee = 0;
        assert(!tx.IsCoinBase());
        // SYSCOIN
        CAssetsMap mapAssetIn, mapAssetOut;
        if(!bFoundConflict)
            assert(Consensus::CheckTxInputs(tx, dummy_state, mempoolDuplicate, spendheight, txfee, mapAssetIn, mapAssetOut));
        // SYSCOIN
        for (const auto& input: tx.vin) if(mempoolDuplicate.HaveCoin(input.prevout)) mempoolDuplicate.SpendCoin(input.prevout);
        AddCoins(mempoolDuplicate, tx, std::numeric_limits<int>::max());
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        uint256 hash = it->second->GetHash();
        indexed_transaction_set::const_iterator it2 = mapTx.find(hash);
        const CTransaction& tx = it2->GetTx();
        assert(it2 != mapTx.end());
        assert(&tx == it->second);
    }

    assert(totalTxSize == checkTotal);
    assert(m_total_fee == check_total_fee);
    assert(innerUsage == cachedInnerUsage);
}

bool CTxMemPool::CompareDepthAndScore(const uint256& hasha, const uint256& hashb, bool wtxid)
{
    /* Return `true` if hasha should be considered sooner than hashb. Namely when:
     *   a is not in the mempool, but b is
     *   both are in the mempool and a has fewer ancestors than b
     *   both are in the mempool and a has a higher score than b
     */
    LOCK(cs);
    indexed_transaction_set::const_iterator j = wtxid ? get_iter_from_wtxid(hashb) : mapTx.find(hashb);
    if (j == mapTx.end()) return false;
    indexed_transaction_set::const_iterator i = wtxid ? get_iter_from_wtxid(hasha) : mapTx.find(hasha);
    if (i == mapTx.end()) return true;
    uint64_t counta = i->GetCountWithAncestors();
    uint64_t countb = j->GetCountWithAncestors();
    if (counta == countb) {
        return CompareTxMemPoolEntryByScore()(*i, *j);
    }
    return counta < countb;
}

namespace {
class DepthAndScoreComparator
{
public:
    bool operator()(const CTxMemPool::indexed_transaction_set::const_iterator& a, const CTxMemPool::indexed_transaction_set::const_iterator& b)
    {
        uint64_t counta = a->GetCountWithAncestors();
        uint64_t countb = b->GetCountWithAncestors();
        if (counta == countb) {
            return CompareTxMemPoolEntryByScore()(*a, *b);
        }
        return counta < countb;
    }
};
} // namespace

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedDepthAndScore() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), DepthAndScoreComparator());
    return iters;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid) const
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    vtxid.clear();
    vtxid.reserve(mapTx.size());

    for (auto it : iters) {
        vtxid.push_back(it->GetTx().GetHash());
    }
}

static TxMempoolInfo GetInfo(CTxMemPool::indexed_transaction_set::const_iterator it) {
    return TxMempoolInfo{it->GetSharedTx(), it->GetTime(), it->GetFee(), it->GetTxSize(), it->GetModifiedFee() - it->GetFee()};
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedDepthAndScore();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

CTransactionRef CTxMemPool::get(const uint256& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

TxMempoolInfo CTxMemPool::info(const GenTxid& gtxid) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i == mapTx.end())
        return TxMempoolInfo();
    return GetInfo(i);
}
// SYSCOIN

bool CTxMemPool::existsProviderTxConflict(
    const CTransaction& tx,
    const CBlockIndex* active_tip,
    std::optional<COutPoint>* pq_operator_collateral) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    if (pq_operator_collateral != nullptr) {
        pq_operator_collateral->reset();
    }
    if (std::any_of(
            tx.vin.begin(), tx.vin.end(), [&](const CTxIn& input) {
                return mapPQUpdateCollaterals.count(input.prevout) != 0;
            })) {
        return true;
    }
    if (!IsBranchBoundProviderTransaction(tx)) return false;
    if (active_tip == nullptr || !deterministicMNManager) return true;

    const auto global{GetPQGlobalKeyPayload(tx)};
    if (tx.nVersion == SYSCOIN_TX_VERSION_PQ_GLOBAL_KEY && !global) {
        return true;
    }
    const auto pq_operator_update{GetPQOperatorUpdate(tx)};
    const auto provider_mutation{GetProviderMutation(tx)};
    const bool is_pq_revoke{
        tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE &&
        pq_operator_update.has_value()};

    // Resolve conflicts that depend only on exact mempool reservations before
    // loading branch state. Apart from avoiding unnecessary snapshot work,
    // this preserves fail-closed conflict detection if the target DMN lookup
    // itself is unavailable.
    if (pq_operator_update &&
        mapPQOperatorUpdates.count(*pq_operator_update) != 0) {
        return true;
    }
    if (provider_mutation &&
        mapPQRevocations.count(*provider_mutation) != 0) {
        return true;
    }
    if (is_pq_revoke && mapProTxRefs.count(*pq_operator_update) != 0) {
        return true;
    }
    if (global &&
        mapPQGlobalKeys.count(global->candidate.public_key) != 0) {
        return true;
    }

    CDeterministicMNList mn_list;
    try {
        mn_list = deterministicMNManager->GetListForBlock(active_tip);
    } catch (const std::exception&) {
        return true;
    }

    const auto collect_ancestor_txids =
        [&](const CTransaction& descendant)
            EXCLUSIVE_LOCKS_REQUIRED(cs) {
            std::vector<uint256> pending;
            pending.reserve(descendant.vin.size());
            for (const auto& input : descendant.vin) {
                pending.push_back(input.prevout.hash);
            }
            std::set<uint256> visited;
            while (!pending.empty()) {
                const uint256 txid{pending.back()};
                pending.pop_back();
                if (!visited.insert(txid).second) continue;
                const auto parent{mapTx.find(txid)};
                if (parent == mapTx.end()) continue;
                for (const auto& input : parent->GetTx().vin) {
                    pending.push_back(input.prevout.hash);
                }
            }
            return visited;
        };

    if (pq_operator_update) {
        const auto dmn{mn_list.GetMN(*pq_operator_update)};
        if (!dmn) {
            // Production callers request admission metadata. Test-only
            // conflict probes may intentionally use a synthetic empty list.
            return pq_operator_collateral != nullptr;
        }
        if (pq_operator_collateral != nullptr) {
            *pq_operator_collateral = dmn->collateralOutpoint;
        }
        if (SpendsOutpoint(tx, dmn->collateralOutpoint) ||
            mapNextTx.count(dmn->collateralOutpoint) != 0 ||
            mapProTxCollaterals.count(dmn->collateralOutpoint) != 0) {
            return true;
        }
    }
    if (provider_mutation) {
        const auto dmn{mn_list.GetMN(*provider_mutation)};
        if (dmn &&
            mapProTxCollaterals.count(dmn->collateralOutpoint) != 0) {
            return true;
        }
    }
    if (global) {
        const std::array<uint256, 1> requested{global->pro_tx_hash};
        llmq::pq::PQRegistryMempoolView view;
        std::string error;
        if (!deterministicMNManager->GetPQRegistryMempoolView(
                active_tip, requested, view, error)) {
            return true;
        }
        const auto* current{view.FindOperator(global->pro_tx_hash)};
        if (current == nullptr) return true;
        const bool introduces_operator{current->state_exists == 0};
        if (!HasPQRegistryCapacity(
                view.operator_state_count, m_pq_operator_introductions,
                introduces_operator ? 1 : 0,
                llmq::pq::MAX_PQ_OPERATOR_STATES)) {
            return true;
        }
    }

    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_REGISTER) {
        CProRegTx payload;
        if (!GetTxPayload(tx, payload) ||
            mapProTxAddresses.count(payload.addr) != 0 ||
            mapProTxPubKeyIDs.count(payload.keyIDOwner) != 0) {
            return true;
        }
        COutPoint collateral{payload.collateralOutpoint};
        if (collateral.hash.IsNull()) {
            collateral.hash = tx.GetHash();
        } else {
            if (mapNextTx.count(collateral) != 0 ||
                mapProTxCollaterals.count(collateral) != 0) {
                return true;
            }
            const auto replaced{mn_list.GetMNByCollateral(collateral)};
            if (replaced) {
                if (mapPQOperatorUpdates.count(replaced->proTxHash) != 0) {
                    return true;
                }
                const auto refs{mapProTxRefs.equal_range(replaced->proTxHash)};
                const auto ancestors{collect_ancestor_txids(tx)};
                for (auto ref = refs.first; ref != refs.second; ++ref) {
                    if (mapTx.find(ref->second) != mapTx.end() &&
                        ancestors.count(ref->second) == 0) {
                        return true;
                    }
                }
            }
        }
        return mapProTxCollaterals.count(collateral) != 0;
    }

    if (tx.nVersion == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        CProUpServTx payload;
        if (!GetTxPayload(tx, payload)) return true;
        if (payload.addr != CService() &&
            mapProTxAddresses.count(payload.addr) != 0) {
            return true;
        }
        if (!payload.vchNEVMAddress.empty() &&
            mapProTxNEVMAddresses.count(payload.vchNEVMAddress) != 0) {
            return true;
        }
    }
    return false;
}

TxMempoolInfo CTxMemPool::info_for_relay(const GenTxid& gtxid, uint64_t last_sequence) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = (gtxid.IsWtxid() ? get_iter_from_wtxid(gtxid.GetHash()) : mapTx.find(gtxid.GetHash()));
    if (i != mapTx.end() && i->GetSequence() < last_sequence) {
        return GetInfo(i);
    } else {
        return TxMempoolInfo();
    }
}

void CTxMemPool::PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta = SaturatingAdd(delta, nFeeDelta);
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            mapTx.modify(it, [&nFeeDelta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(nFeeDelta); });
            // Now update all ancestors' modified fees with descendants
            auto ancestors{AssumeCalculateMemPoolAncestors(__func__, *it, Limits::NoLimits(), /*fSearchForParents=*/false)};
            for (txiter ancestorIt : ancestors) {
                mapTx.modify(ancestorIt, [=](CTxMemPoolEntry& e){ e.UpdateDescendantState(0, nFeeDelta, 0);});
            }
            // Now update all descendants' modified fees with ancestors
            setEntries setDescendants;
            CalculateDescendants(it, setDescendants);
            setDescendants.erase(it);
            for (txiter descendantIt : setDescendants) {
                mapTx.modify(descendantIt, [=](CTxMemPoolEntry& e){ e.UpdateAncestorState(0, nFeeDelta, 0, 0); });
            }
            ++nTransactionsUpdated;
        }
        if (delta == 0) {
            mapDeltas.erase(hash);
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) delta cleared\n", hash.ToString(), it == mapTx.end() ? "not " : "");
        } else {
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) fee += %s, new delta=%s\n",
                      hash.ToString(),
                      it == mapTx.end() ? "not " : "",
                      FormatMoney(nFeeDelta),
                      FormatMoney(delta));
        }
    }
}

void CTxMemPool::ApplyDelta(const uint256& hash, CAmount &nFeeDelta) const
{
    AssertLockHeld(cs);
    std::map<uint256, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const uint256& hash)
{
    AssertLockHeld(cs);
    mapDeltas.erase(hash);
}

std::vector<CTxMemPool::delta_info> CTxMemPool::GetPrioritisedTransactions() const
{
    AssertLockNotHeld(cs);
    LOCK(cs);
    std::vector<delta_info> result;
    result.reserve(mapDeltas.size());
    for (const auto& [txid, delta] : mapDeltas) {
        const auto iter{mapTx.find(txid)};
        const bool in_mempool{iter != mapTx.end()};
        std::optional<CAmount> modified_fee;
        if (in_mempool) modified_fee = iter->GetModifiedFee();
        result.emplace_back(delta_info{in_mempool, delta, modified_fee, txid});
    }
    return result;
}

const CTransaction* CTxMemPool::GetConflictTx(const COutPoint& prevout) const
{
    const auto it = mapNextTx.find(prevout);
    return it == mapNextTx.end() ? nullptr : it->second;
}

std::optional<CTxMemPool::txiter> CTxMemPool::GetIter(const uint256& txid) const
{
    auto it = mapTx.find(txid);
    if (it != mapTx.end()) return it;
    return std::nullopt;
}

CTxMemPool::setEntries CTxMemPool::GetIterSet(const std::set<uint256>& hashes) const
{
    CTxMemPool::setEntries ret;
    for (const auto& h : hashes) {
        const auto mi = GetIter(h);
        if (mi) ret.insert(*mi);
    }
    return ret;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GetIterVec(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> ret;
    ret.reserve(txids.size());
    for (const auto& txid : txids) {
        const auto it{GetIter(txid)};
        if (!it) return {};
        ret.push_back(*it);
    }
    return ret;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(GenTxid::Txid(tx.vin[i].prevout.hash)))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    // Check to see if the inputs are made available by another tx in the package.
    // These Coins would not be available in the underlying CoinsView.
    if (auto it = m_temp_added.find(outpoint); it != m_temp_added.end()) {
        coin = it->second;
        return true;
    }

    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            coin = Coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            m_non_base_coins.emplace(outpoint);
            return true;
        } else {
            return false;
        }
    }
    return base->GetCoin(outpoint, coin);
}

void CCoinsViewMemPool::PackageAddTransaction(const CTransactionRef& tx)
{
    for (unsigned int n = 0; n < tx->vout.size(); ++n) {
        m_temp_added.emplace(COutPoint(tx->GetHash(), n), Coin(tx->vout[n], MEMPOOL_HEIGHT, false));
        m_non_base_coins.emplace(tx->GetHash(), n);
    }
}
void CCoinsViewMemPool::Reset()
{
    m_temp_added.clear();
    m_non_base_coins.clear();
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 15 pointers + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 15 * sizeof(void*)) *
               mapTx.size() +
           memusage::DynamicUsage(mapNextTx) +
           memusage::DynamicUsage(mapDeltas) +
           memusage::DynamicUsage(vTxHashes) +
           // SYSCOIN: Include every bounded PQ/provider reservation index.
           memusage::DynamicUsage(mapPQOperatorUpdates) +
           memusage::DynamicUsage(mapPQUpdateCollaterals) +
           memusage::DynamicUsage(mapPQUpdateCollateralByTx) +
           memusage::DynamicUsage(mapPQRevocations) +
           memusage::DynamicUsage(mapPQGlobalKeys) +
           memusage::DynamicUsage(mapPQGlobalReservations) +
           memusage::DynamicUsage(mapProTxAddresses) +
           memusage::DynamicUsage(mapProTxNEVMAddresses) +
           memusage::DynamicUsage(mapProTxPubKeyIDs) +
           memusage::DynamicUsage(mapProTxCollaterals) +
           cachedInnerUsage;
}

void CTxMemPool::RemoveUnbroadcastTx(const uint256& txid, const bool unchecked) {
    LOCK(cs);

    if (m_unbroadcast_txids.erase(txid))
    {
        LogPrint(BCLog::MEMPOOL, "Removed %i from set of unbroadcast txns%s\n", txid.GetHex(), (unchecked ? " before confirmation that txn was sent out" : ""));
    }
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    UpdateForRemoveFromMempool(stage, updateDescendants);
    for (txiter it : stage) {
        removeUnchecked(it, reason);
    }
}

int CTxMemPool::Expire(std::chrono::seconds time)
{
    AssertLockHeld(cs);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    setEntries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        toremove.insert(mapTx.project<0>(it));
        it++;
    }
    setEntries stage;
    for (txiter removeit : toremove) {
        CalculateDescendants(removeit, stage);
    }
    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

// SYSCOIN: Forward branch-bound PQ reservation context to full insertion.
bool CTxMemPool::addUnchecked(
    const CTxMemPoolEntry& entry,
    bool validFeeEstimate,
    const CBlockIndex* pq_registry_tip,
    std::optional<COutPoint> pq_operator_collateral)
{
    auto ancestors{AssumeCalculateMemPoolAncestors(__func__, entry, Limits::NoLimits())};
    return addUnchecked(entry, ancestors, validFeeEstimate,
                        pq_registry_tip, std::move(pq_operator_collateral));
}

void CTxMemPool::UpdateChild(txiter entry, txiter child, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Children s;
    if (add && entry->GetMemPoolChildren().insert(*child).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolChildren().erase(*child)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

void CTxMemPool::UpdateParent(txiter entry, txiter parent, bool add)
{
    AssertLockHeld(cs);
    CTxMemPoolEntry::Parents s;
    if (add && entry->GetMemPoolParents().insert(*parent).second) {
        cachedInnerUsage += memusage::IncrementalDynamicUsage(s);
    } else if (!add && entry->GetMemPoolParents().erase(*parent)) {
        cachedInnerUsage -= memusage::IncrementalDynamicUsage(s);
    }
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(llround(rollingMinimumFeeRate));

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)m_incremental_relay_feerate.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), m_incremental_relay_feerate);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    AssertLockHeld(cs);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);
    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        indexed_transaction_set::index<descendant_score>::type::iterator it = mapTx.get<descendant_score>().begin();

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        CFeeRate removed(it->GetModFeesWithDescendants(), it->GetSizeWithDescendants());
        removed += m_incremental_relay_feerate;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        setEntries stage;
        CalculateDescendants(mapTx.project<0>(it), stage);
        nTxnRemoved += stage.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(stage.size());
            for (txiter iter : stage)
                txn.push_back(iter->GetTx());
        }
        RemoveStaged(stage, false, MemPoolRemovalReason::SIZELIMIT);
        if (pvNoSpendsRemaining) {
            for (const CTransaction& tx : txn) {
                for (const CTxIn& txin : tx.vin) {
                    if (exists(GenTxid::Txid(txin.prevout.hash))) continue;
                    pvNoSpendsRemaining->push_back(txin.prevout);
                }
            }
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0)) {
        LogPrint(BCLog::MEMPOOL, "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}


uint64_t CTxMemPool::CalculateDescendantMaximum(txiter entry) const {
    // find parent with highest descendant count
    std::vector<txiter> candidates;
    setEntries counted;
    candidates.push_back(entry);
    uint64_t maximum = 0;
    while (candidates.size()) {
        txiter candidate = candidates.back();
        candidates.pop_back();
        if (!counted.insert(candidate).second) continue;
        const CTxMemPoolEntry::Parents& parents = candidate->GetMemPoolParentsConst();
        if (parents.size() == 0) {
            maximum = std::max(maximum, candidate->GetCountWithDescendants());
        } else {
            for (const CTxMemPoolEntry& i : parents) {
                candidates.push_back(mapTx.iterator_to(i));
            }
        }
    }
    return maximum;
}

void CTxMemPool::GetTransactionAncestry(const uint256& txid, size_t& ancestors, size_t& descendants, size_t* const ancestorsize, CAmount* const ancestorfees) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    ancestors = descendants = 0;
    if (it != mapTx.end()) {
        ancestors = it->GetCountWithAncestors();
        if (ancestorsize) *ancestorsize = it->GetSizeWithAncestors();
        if (ancestorfees) *ancestorfees = it->GetModFeesWithAncestors();
        descendants = CalculateDescendantMaximum(it);
    }
}

bool CTxMemPool::GetLoadTried() const
{
    LOCK(cs);
    return m_load_tried;
}

void CTxMemPool::SetLoadTried(bool load_tried)
{
    LOCK(cs);
    m_load_tried = load_tried;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GatherClusters(const std::vector<uint256>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> clustered_txs{GetIterVec(txids)};
    // Use epoch: visiting an entry means we have added it to the clustered_txs vector. It does not
    // necessarily mean the entry has been processed.
    WITH_FRESH_EPOCH(m_epoch);
    for (const auto& it : clustered_txs) {
        visited(it);
    }
    // i = index of where the list of entries to process starts
    for (size_t i{0}; i < clustered_txs.size(); ++i) {
        // DoS protection: if there are 500 or more entries to process, just quit.
        if (clustered_txs.size() > 500) return {};
        const txiter& tx_iter = clustered_txs.at(i);
        for (const auto& entries : {tx_iter->GetMemPoolParentsConst(), tx_iter->GetMemPoolChildrenConst()}) {
            for (const CTxMemPoolEntry& entry : entries) {
                const auto entry_it = mapTx.iterator_to(entry);
                if (!visited(entry_it)) {
                    clustered_txs.push_back(entry_it);
                }
            }
        }
    }
    return clustered_txs;
}
