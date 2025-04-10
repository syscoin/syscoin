// Copyright (c) 2013-2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <services/nevmconsensus.h>
#include <services/assetconsensus.h>
#include <validation.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <nevm/nevm.h>
#include <nevm/address.h>
#include <nevm/sha3.h>
#include <messagesigner.h>
#include <logging.h>
#include <util/rbf.h>
#include <undo.h>
#include <validationinterface.h>
#include <timedata.h>
#include <key_io.h>
#include <logging.h>
#include <node/context.h>
#include <node/transaction.h>
std::unique_ptr<CBlockIndexDB> pblockindexdb;
std::unique_ptr<CNEVMDataDB> pnevmdatadb;
bool fNEVMConnection = false;
bool fRegTest = false;
bool fSigNet = false;

bool DisconnectSyscoinTransaction(const CTransaction& tx, NEVMMintTxSet &setMintTxs) {
 
    if(IsSyscoinMintTx(tx.nVersion)) {
        if(!DisconnectMintAsset(tx, setMintTxs))
            return false;       
    }
    return true;       
}

void CNEVMDataDB::FlushDataToCache(const PoDAMAPMemory &mapPoDA) {
    LOCK(cs_cache);
    if(mapPoDA.empty()) {
        return;
    }
    for (auto const& [key, val] : mapPoDA) {
        auto inserted = mapCache.try_emplace(key, val);
        // for duplicate blobs, allow override with some fields
        if(!inserted.second) {
            inserted.first->second.nMedianTime = val.nMedianTime;
            inserted.first->second.txid = val.txid;
        }
    }
}
size_t CNEVMDataDB::GetCacheMemoryUsage() const
{
    LOCK(cs_cache);
    size_t total = 0;
    for (auto const& [key, val] : mapCache) {
        total += val.nSize;
    }
    return total;
}
PoDACacheSizeState CNEVMDataDB::GetPoDACacheSizeState(size_t &cacheSize) {
    cacheSize = GetCacheMemoryUsage();
    // 1GB limit for cache for PoDA
    static const size_t PODA_CACHE_LIMIT = 1024 * 1024 * 1024; 
    // You can define thresholds for LARGE/CRITICAL
    if (cacheSize > PODA_CACHE_LIMIT * 0.95) {
        return PoDACacheSizeState::CRITICAL;
    } else if (cacheSize > PODA_CACHE_LIMIT * 0.90) {
        return PoDACacheSizeState::LARGE;
    }
    return PoDACacheSizeState::OK;
}
bool CNEVMDataDB::FlushCacheToDisk(ChainstateManager& chainman, const int64_t nMedianTime) {
    bool cacheEmpty = false;
    {
        LOCK(cs_cache);
        cacheEmpty = mapCache.empty();
    }
    if(cacheEmpty) {
        if(fTestNet) {
            return PruneStandalone(chainman, nMedianTime);
        }
        return true;
    }
    LOCK(cs_cache);
    CDBBatch batch(*this);    
    // only prune on testnet flush, mainnet relies only on CL
    if(fTestNet) {
        if (!PruneToBatch(chainman, batch, nMedianTime)) {
            LogPrint(BCLog::SYS, "Error: Could not prune nevm blobs\n");
            return false;
        }
    }
    for (auto const& [key, val] : mapCache) {
        batch.Write(key, val);
    }
    if(mapCache.size() > 0)
        LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm blobs\n", mapCache.size());
    bool res = WriteBatch(batch, true);
    if(res) {
        mapCache.clear();
    }
    return res;
}
std::optional<CNEVMData> CNEVMDataDB::ReadData(const std::vector<uint8_t>& nVersionHash) {
    
    return std::nullopt;
}

bool CNEVMDataDB::FlushErase(const NEVMDataVec &vecDataKeys) {
    LOCK(cs_cache);
    if(vecDataKeys.empty())
        return true;
    CDBBatch batch(*this);    
    for (const auto &key : vecDataKeys) {
        batch.Erase(key);
        auto it = mapCache.find(key);
        if(it != mapCache.end())
            mapCache.erase(it);
    }
    if(vecDataKeys.size() > 0)
        LogPrint(BCLog::SYS, "Flushing, erasing %d nevm blob keys\n", vecDataKeys.size());
    return WriteBatch(batch, true);
}
bool CNEVMDataDB::BlobExists(const std::vector<uint8_t>& vchVersionHash) {
    LOCK(cs_cache);
    return (mapCache.find(vchVersionHash) != mapCache.end()) || Exists(vchVersionHash);
}
bool CNEVMDataDB::GetBlobMetaData(const std::vector<uint8_t>& vchVersionHash, MapPoDAPayloadMeta& meta) {
    LOCK(cs_cache);
    auto it = mapCache.find(vchVersionHash);
    if (it != mapCache.end()) {
        meta = it->second;
        return true;
    } 
    if(Exists(vchVersionHash)) {
        return Read(vchVersionHash, meta);
    }
    return false;
}
const PoDAMAPMemory& CNEVMDataDB::GetCache() const {
    AssertLockHeld(cs_cache);
    return mapCache;
}

bool CNEVMDataDB::PruneToBatch(
    ChainstateManager& chainman,
    CDBBatch& batch,
    const int64_t nMedianTime)
{
    AssertLockHeld(cs_cache);
    int nCount = 0;
    auto it = mapCache.begin();
    while (it != mapCache.end()) {
        const int64_t entryTime = it->second.nMedianTime;
        bool isExpired = nMedianTime > (entryTime + NEVM_DATA_EXPIRE_TIME);
        if (isExpired) {
            it = mapCache.erase(it);
            ++nCount;
        } else {
            ++it;
        }
    }
    
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->SeekToFirst();
    std::vector<uint8_t> vchVersionHash;
    MapPoDAPayloadMeta meta;
    while (pcursor->Valid()) {
        try {
            if (!pcursor->GetKey(vchVersionHash)) {
                pcursor->Next();
                continue;
            }
            if (pcursor->GetValue(meta)) {
                bool isExpired = nMedianTime > (meta.nMedianTime + NEVM_DATA_EXPIRE_TIME);
                if (isExpired) {
                    batch.Erase(vchVersionHash);
                    ++nCount;
                }
            }
            pcursor->Next();
        } catch (const std::exception& e) {
            return error("%s() : deserialize error: %s", __func__, e.what());
        }
    }
    if(nCount > 0)
        LogPrint(BCLog::SYS, "PruneToBatch pruned %d nevm blobs\n", nCount);

    return true;
}

bool CNEVMDataDB::PruneStandalone(ChainstateManager& chainman, const int64_t nMedianTime)
{
    LOCK(cs_cache);
    CDBBatch batch(*this);
    if (!PruneToBatch(chainman, batch, nMedianTime)) {
        return false;
    }
    return WriteBatch(batch, true);
}