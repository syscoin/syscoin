// Copyright (c) 2017-2018 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_SERVICES_NEVMCONSENSUS_H
#define SYSCOIN_SERVICES_NEVMCONSENSUS_H
#include <primitives/transaction.h>
#include <dbwrapper.h>
#include <consensus/params.h>
#include <util/hasher.h>
#include <sync.h>
class TxValidationState;
class CCoinsViewCache;
class CTxUndo;
class CBlock;
class BlockValidationState;
class CBlockIndexDB;
class CNEVMData;
class CDBBatch;
class ChainstateManager;
enum class PoDACacheSizeState {
    OK,
    LARGE,
    CRITICAL,
};
namespace node {
    struct NodeContext;
    } // namespace node
    
class CNEVMDataDB : public CDBWrapper {
public:
    mutable Mutex cs_cache; // Mutex to protect cache operations
private:
    PoDAMAPMemory mapCache GUARDED_BY(cs_cache);
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const NEVMDataVec &vecDataKeys) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushCacheToDisk(ChainstateManager& chainman, const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    void FlushDataToCache(const PoDAMAPMemory &mapPoDA) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    std::optional<CNEVMData> ReadData(const node::NodeContext& node, const std::vector<uint8_t>& nVersionHash) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool PruneStandalone(ChainstateManager& chainman, const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool PruneToBatch(ChainstateManager& chainman, CDBBatch& batch, const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
    bool GetBlobMetaData(const std::vector<uint8_t>& vchVersionhash, MapPoDAPayloadMeta& meta) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool BlobExists(const std::vector<uint8_t>& vchVersionhash) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    const PoDAMAPMemory& GetCache() const EXCLUSIVE_LOCKS_REQUIRED(cs_cache);
    size_t GetCacheMemoryUsage() const EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    PoDACacheSizeState GetPoDACacheSizeState(size_t &cacheSize) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
};
extern std::unique_ptr<CNEVMDataDB> pnevmdatadb;
bool DisconnectSyscoinTransaction(const CTransaction& tx, NEVMMintTxSet &setMintTxs);
#endif // SYSCOIN_SERVICES_NEVMCONSENSUS_H
