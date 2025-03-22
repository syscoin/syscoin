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

void CNEVMDataDB::FlushDataToCache(const PoDAMAPMemory &mapPoDA, const int64_t nMedianTime) {
    LOCK(cs_cache);
    if(mapPoDA.empty()) {
        return;
    }
    for (auto const& [key, val] : mapPoDA) {
        // Could be null if we are reindexing blocks from disk and we get the VH without data (because data wasn't provided in payload).
        // This is OK because we still want to provide the VH's to NEVM for indexing into DB (lookup via precompile).
        if(!val) {
            continue;
        }
        // mapPoDA has a pointer of data back to tx vout and we copy it here because the block will lose its memory soon as its
        // stored to disk we create a copy here in our cache (which later gets written to disk in FlushStateToDisk)
        auto inserted = mapCache.try_emplace(key, /* data */ *val, /* MTP */ nMedianTime);
        // for duplicate blobs, allow to update median time
        if(!inserted.second) {
            inserted.first->second.second = nMedianTime;
        }
    }
}
size_t CNEVMDataDB::GetCacheMemoryUsage() const
{
    LOCK(cs_cache);
    size_t total = 0;
    for (const auto &it : mapCache) {
        total += it.second.first.size();
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
bool CNEVMDataDB::FlushCacheToDisk(const int64_t nMedianTime) {
    LOCK(cs_cache);
    if(mapCache.empty()) {
        return true;
    }
    CDBBatch batch(*this);    
    for (auto const& [key, val] : mapCache) {
        const auto pairData = std::make_pair(key, true);
        const auto pairMTP = std::make_pair(key, false);
        // write the size of the data
        batch.Write(key, (uint32_t)val.first.size());
        // write the data
        batch.Write(pairData, val.first);
        // write the MTP
        batch.Write(pairMTP, val.second);
    }
    // only prune on testnet flush, mainnet relies only on CL
    if(fTestNet) {
        if (!PruneToBatch(batch, nMedianTime)) {
            LogPrint(BCLog::SYS, "Error: Could not prune nevm blobs\n");
            return false;
        }
    }
    if(mapCache.size() > 0)
        LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm blobs\n", mapCache.size());
    bool res = WriteBatch(batch, true);
    if(res) {
        mapCache.clear();
    }
    return res;
}
bool CNEVMDataDB::ReadData(const std::vector<uint8_t>& nVersionHash, std::vector<uint8_t>& vchData) {
    LOCK(cs_cache);
    auto it = mapCache.find(nVersionHash);
    if(it != mapCache.end()){
        vchData = it->second.first;
        return true;
    } else {
        const auto pair = std::make_pair(nVersionHash, true);
        return Read(pair, vchData);
    }
    return false;
} 
bool CNEVMDataDB::ReadMTP(const std::vector<uint8_t>& nVersionHash, int64_t &nMedianTime) {
    LOCK(cs_cache);
    auto it = mapCache.find(nVersionHash);
    if(it != mapCache.end()){
        nMedianTime = it->second.second;
        return true;
    } else {
        const auto pair = std::make_pair(nVersionHash, false);
        return Read(pair, nMedianTime);
    }
    return false;
}
bool CNEVMDataDB::ReadDataSize(const std::vector<uint8_t>& nVersionHash, uint32_t &nSize) {
    LOCK(cs_cache);
    auto it = mapCache.find(nVersionHash);
    if(it != mapCache.end()){
        nSize = it->second.first.size();
        return true;
    } else {
        return Read(nVersionHash, nSize);
    }
    return false;
}
bool CNEVMDataDB::FlushErase(const NEVMDataVec &vecDataKeys) {
    LOCK(cs_cache);
    if(vecDataKeys.empty())
        return true;
    CDBBatch batch(*this);    
    for (const auto &key : vecDataKeys) {
        const auto pairData = std::make_pair(key, true);
        const auto pairMTP = std::make_pair(key, false);
        // erase size
        batch.Erase(key);
        // erase data and MTP keys
        if(Exists(pairData)) {
            batch.Erase(pairData);
        }
        if(Exists(pairMTP))   
            batch.Erase(pairMTP);
        // remove from cache as well
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
    return (mapCache.find(vchVersionHash) != mapCache.end()) || Exists(std::make_pair(vchVersionHash, true));
}

PoDAMAP CNEVMDataDB::GetCacheCopy() const {
    LOCK(cs_cache);
    return mapCache;  // Returns a copy of the cache map
}

bool CNEVMDataDB::PruneToBatch(
    CDBBatch& batch,
    const int64_t nMedianTime)
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->SeekToFirst();
    std::pair<std::vector<unsigned char>, bool> pair;
    int64_t nTime   = 0;
    int count       = 0;
    while (pcursor->Valid()) {
        try {
            nTime = 0;
            if (!pcursor->GetKey(pair) || pair.second) {
                pcursor->Next();
                continue; // Not an MTP key or is the (versionHash, true) data key
            }
            // So this is (versionHash, false) => MTP entry
            if (pcursor->GetValue(nTime)) {
                bool isExpired = nMedianTime > (nTime + NEVM_DATA_EXPIRE_TIME);
                if (isExpired) {
                    // Erase MTP
                    batch.Erase(pair);

                    // Erase data key if it exists
                    pair.second = true;
                    if (Exists(pair)) {
                        batch.Erase(pair);
                    }
                    // Erase size
                    batch.Erase(pair.first);
                    count++;
                }
            }
            pcursor->Next();
        } catch (const std::exception& e) {
            return error("%s() : deserialize error: %s", __func__, e.what());
        }
    }
    if(count > 0)
        LogPrint(BCLog::SYS, "PruneToBatch pruned %d nevm blobs\n", count);

    return true;
}

bool CNEVMDataDB::PruneStandalone(const int64_t nMedianTime)
{
    LOCK(cs_cache);
    int nCount = 0;
    auto it = mapCache.begin();
    while (it != mapCache.end()) {
        const int64_t entryTime = it->second.second;
        bool isExpired = nMedianTime > (entryTime + NEVM_DATA_EXPIRE_TIME);
        if (isExpired) {
            it = mapCache.erase(it);
        } else {
            ++it;
        }
        ++nCount;
    }
    CDBBatch batch(*this);
    if (!PruneToBatch(batch, nMedianTime)) {
        return false;
    }
    if(nCount > 0)
        LogPrint(BCLog::SYS, "PruneStandalone, pruning %d nevm blobs\n", nCount);
    return WriteBatch(batch, true);
}