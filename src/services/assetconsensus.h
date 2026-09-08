// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_ASSETCONSENSUS_H
#define SYSCOIN_SERVICES_ASSETCONSENSUS_H
#include <primitives/transaction.h>
#include <dbwrapper.h>
#include <consensus/params.h>
#include <util/hasher.h>
#include <sync.h>

#include <cstddef>

namespace nevm_cache_detail {
/** The caller must hold the cache lock; callbacks must not modify the cache. */
template <typename Cache, typename AddToBatch, typename WriteBatch>
bool FlushCache(CDBWrapper& db, Cache& cache, std::size_t chunk_items, bool sync,
                AddToBatch add_to_batch, WriteBatch write_batch)
{
    CDBBatch batch(db);
    auto first = cache.begin();
    while (first != cache.end()) {
        auto last = first;
        std::size_t items{0};
        do {
            add_to_batch(batch, *last);
            ++last;
            ++items;
        } while (last != cache.end() && items != chunk_items);

        // A zero chunk limit preserves the unbounded-batch behavior. Keep the
        // entire pending range visible if writing returns false or throws.
        if (!write_batch(batch, sync)) return false;
        first = cache.erase(first, last);
        batch.Clear();
    }
    return true;
}
} // namespace nevm_cache_detail

class TxValidationState;
class CTxUndo;
class CBlock;
// SYSCOIN BEGIN: Retain uncommitted cache deletions until their write succeeds.
class CNEVMTxRootsDB : public CDBWrapper {
    NEVMTxRootMap mapCache;
    mutable Mutex cs_cache; // Mutex to protect cache operations (non-recursive for better performance)
    NEVMMintTxSet m_pending_erases GUARDED_BY(cs_cache);
    void StageErase(const std::vector<uint256>& block_hashes) EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
    bool FlushPendingErases() EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
protected:
    virtual bool WriteCacheBatch(CDBBatch& batch, bool sync) { return CDBWrapper::WriteBatch(batch, sync); }
public:
    using CDBWrapper::CDBWrapper;
    virtual ~CNEVMTxRootsDB() = default;
    void EraseCache(const std::vector<uint256>& block_hashes) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushErase(const std::vector<uint256> &vecBlockHashes) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool ReadTxRoots(const uint256& nBlockHash, NEVMTxRoot& txRoot) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushCacheToDisk(std::size_t CHUNK_ITEMS = 100000, bool fSync = true) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    void FlushDataToCache(const NEVMTxRootMap &mapNEVMTxRoots) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
};

class CNEVMMintedTxDB : public CDBWrapper {
    NEVMMintTxSet mapCache;
    mutable Mutex cs_cache; // Mutex to protect cache operations (non-recursive for better performance)
    NEVMMintTxSet m_pending_erases GUARDED_BY(cs_cache);
    void StageErase(const NEVMMintTxSet& tx_hashes) EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
    bool FlushPendingErases() EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
protected:
    virtual bool WriteCacheBatch(CDBBatch& batch, bool sync) { return CDBWrapper::WriteBatch(batch, sync); }
public:
    using CDBWrapper::CDBWrapper;
    virtual ~CNEVMMintedTxDB() = default;
    void EraseCache(const NEVMMintTxSet& tx_hashes) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushErase(const NEVMMintTxSet &setMintTxs) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushCacheToDisk(std::size_t CHUNK_ITEMS = 256, bool fSync = true) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    void FlushDataToCache(const NEVMMintTxSet &mapNEVMTxRoots) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool ExistsTx(const uint256& nTxHash) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
};
// SYSCOIN END: Retain uncommitted cache deletions until their write succeeds.

extern std::unique_ptr<CNEVMTxRootsDB> pnevmtxrootsdb;
extern std::unique_ptr<CNEVMMintedTxDB> pnevmtxmintdb;
bool DisconnectMintAsset(const CTransaction &tx, NEVMMintTxSet &setMintTxs);
bool CheckSyscoinMint(const CTransaction& tx, 
    const uint256& txHash,
    TxValidationState &tstate,
    const uint32_t& nHeight, 
    const bool &fJustCheck, 
    NEVMMintTxSet &setMintTxs, 
    CAssetsMap &mapAssetIn, 
    CAssetsMap &mapAssetOut);
bool CheckSyscoinMintInternal(const CMintSyscoin &mintSyscoin,
    TxValidationState &state,
    const bool &fJustCheck,
    const bool fBridgeCanonicalActive,
    const uint32_t &nHeight,
    NEVMMintTxSet &setMintTxs,
    uint64_t &nAssetFromLog,
    CAmount &outputAmount,
    std::string &witnessAddress);
bool CheckSyscoinInputs(const Consensus::Params& params, 
    const CTransaction& tx, 
    const uint256& txHash, 
    TxValidationState &tstate, 
    const uint32_t &nHeight, 
    const bool &fJustCheck, 
    NEVMMintTxSet &setMintTxs, 
    CAssetsMap& mapAssetIn, 
    CAssetsMap& mapAssetOut);
bool CheckAssetAllocationInputs(const CTransaction &tx, 
    const uint256& txHash, 
    TxValidationState &tstate, 
    const uint32_t &nHeight, 
    const bool &fJustCheck, 
    CAssetsMap &mapAssetIn, 
    CAssetsMap &mapAssetOut);
std::string stringFromSyscoinTx(const int &nVersion);
#endif // SYSCOIN_SERVICES_ASSETCONSENSUS_H
