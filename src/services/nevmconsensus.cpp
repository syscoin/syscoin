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

bool DisconnectSyscoinTransaction(const CTransaction& tx, NEVMMintTxSet &setMintTxs, NEVMDataVec &NEVMDataVecOut) {
 
    if(IsSyscoinMintTx(tx.nVersion)) {
        if(!DisconnectMintAsset(tx, setMintTxs))
            return false;       
    }
    else {
        if (tx.IsNEVMData()) {
            CNEVMData nevmData(tx);
            if(nevmData.IsNull()) {
                LogPrint(BCLog::SYS,"DisconnectSyscoinTransaction: nevm-data-invalid\n");
                return false; 
            }
            NEVMDataVecOut.emplace_back(nevmData.vchVersionHash); 
        } 
    } 
    return true;       
}

void CNEVMDataDB::FlushDataToCache(const PoDAMAPMemory &mapPoDA, const int64_t& nMedianTime) {
    if(mapPoDA.empty()) {
        return;
    }
    int nCount = 0;
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
        nCount++;
    }
    if(nCount > 0)
        LogPrint(BCLog::SYS, "Flushing to cache, storing %d nevm blobs\n", nCount);
}
bool CNEVMDataDB::FlushCacheToDisk() {
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
    LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm blobs\n", mapCache.size());
    auto res = WriteBatch(batch, true);
    mapCache.clear();
    return res;
}
bool CNEVMDataDB::ReadData(const std::vector<uint8_t>& nVersionHash, std::vector<uint8_t>& vchData) {
    
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
    auto it = mapCache.find(nVersionHash);
    if(it != mapCache.end()){
        nSize = it->second.first.size();
        return true;
    } else {
        return Read(nVersionHash, nSize);
    }
    return false;
}
bool CNEVMDataDB::FlushEraseMTPs(const NEVMDataVec &vecDataKeys) {
    if(vecDataKeys.empty())
        return true;
    CDBBatch batch(*this);    
    for (const auto &key : vecDataKeys) {
        const auto pairMTP = std::make_pair(key, false);
        // only set if it already exists (override) rather than create a new insertion
        if(Exists(pairMTP))   
            batch.Write(pairMTP, 0);
        // set in cache as well
        auto it = mapCache.find(key);
        if(it != mapCache.end()) {
            it->second.second = 0;
        }
    }
    LogPrint(BCLog::SYS, "Flushing, resetting %d nevm MTPs\n", vecDataKeys.size());
    return WriteBatch(batch, true);
}
bool CNEVMDataDB::FlushErase(const NEVMDataVec &vecDataKeys) {
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
    LogPrint(BCLog::SYS, "Flushing, erasing %d nevm entries\n", vecDataKeys.size());
    return WriteBatch(batch, true);
}
bool CNEVMDataDB::BlobExists(const std::vector<uint8_t>& vchVersionHash) {
    return (mapCache.find(vchVersionHash) != mapCache.end()) || Exists(std::make_pair(vchVersionHash, true));
}
bool CNEVMDataDB::Prune(const int64_t nMedianTime) {
    auto it = mapCache.begin();
    while (it != mapCache.end()) {
        const bool isExpired = (nMedianTime > (it->second.second+NEVM_DATA_EXPIRE_TIME));
        if (it->second.second > 0 && isExpired) {
            mapCache.erase(it++);
        }
        else {
            ++it;
        }
    }
    CDBBatch batch(*this);
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->SeekToFirst();
    std::pair<std::vector<unsigned char>, bool> pair;
    int64_t nTime;
    while (pcursor->Valid()) {
        try {
            nTime = 0;
            // check if expired if so delete data
            if(pcursor->GetKey(pair) && pair.second == false && pcursor->GetValue(nTime) && nTime > 0 && nMedianTime > (nTime+NEVM_DATA_EXPIRE_TIME)) {
                // erase both pairs
                batch.Erase(pair);
                pair.second = true;
                if(Exists(pair)) {  
                    batch.Erase(pair);
                }
                // erase size
                batch.Erase(pair.first);
            }
            pcursor->Next();
        }
        catch (std::exception &e) {
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    return WriteBatch(batch, true);
}