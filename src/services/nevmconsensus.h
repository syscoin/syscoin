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
enum class PoDACacheSizeState {
    OK,
    LARGE,
    CRITICAL,
};
class CNEVMDataDB : public CDBWrapper {
private:
    PoDAMAP mapCache;
    mutable Mutex cs_cache; // Mutex to protect cache operations
public:
    using CDBWrapper::CDBWrapper;
    bool FlushErase(const NEVMDataVec &vecDataKeys) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool FlushCacheToDisk(const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    void FlushDataToCache(const PoDAMAPMemory &mapPoDA, const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool ReadData(const std::vector<uint8_t>& nVersionHash, std::vector<uint8_t>& vchData) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool ReadDataSize(const std::vector<uint8_t>& nVersionHash, uint32_t &nSize) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool ReadMTP(const std::vector<uint8_t>& nVersionHash, int64_t &nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool PruneStandalone(const int64_t nMedianTime) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    bool PruneToBatch(CDBBatch& batch, const int64_t nMedianTime);
    bool BlobExists(const std::vector<uint8_t>& vchVersionhash) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    PoDAMAP GetCacheCopy() const EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    size_t GetCacheMemoryUsage() const EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
    PoDACacheSizeState GetPoDACacheSizeState(size_t &cacheSize) EXCLUSIVE_LOCKS_REQUIRED(!cs_cache);
};
extern std::unique_ptr<CNEVMDataDB> pnevmdatadb;
bool DisconnectSyscoinTransaction(const CTransaction& tx, NEVMMintTxSet &setMintTxs);
#endif // SYSCOIN_SERVICES_NEVMCONSENSUS_H
