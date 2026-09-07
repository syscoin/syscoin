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

#include <algorithm>

std::unique_ptr<CBlockIndexDB> pblockindexdb;
std::unique_ptr<CNEVMDataDB> pnevmdatadb;
std::unique_ptr<CNEVMDataBlobDB> pnevmdatablobdb;
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

void CNEVMDataDB::FlushDataToCache(const PoDAMAPMemory& mapPoDA, PoDAFlushSource source)
{
    LOCK(cs_cache);
    if (mapPoDA.empty()) return;

    PoDAMAPMemory cache_updates;
    std::map<std::vector<uint8_t>, uint256> owner_updates;
    NEVMDataVec retained_keys;
    CDBBatch batchblob(*pnevmdatablobdb);
    for (const auto& [key, val] : mapPoDA) {
        const bool have_payload = val.vchNEVMData && !val.vchNEVMData->empty();
        MapPoDAPayloadMeta meta;
        const auto cached = mapCache.find(key);
        bool have_metadata = cached != mapCache.end();
        if (have_metadata) {
            meta = cached->second;
        } else {
            have_metadata = Read(key, meta);
            // An unreadable existing row is not evidence of a new mempool blob.
            if (!have_metadata && Exists(key)) continue;
        }
        // Optional sidecar omissions still identify retained references, but do
        // not provide a size or enough information to create a new blob record.
        if (!have_metadata && !have_payload) continue;
        if (have_metadata && have_payload && meta.nSize != val.nSize) continue;

        const bool have_blob = have_payload && pnevmdatablobdb->Exists(key);
        if (have_payload && !have_blob) {
            batchblob.Write(key, val.vchNEVMData);
        }
        if (have_metadata && source == PoDAFlushSource::Mempool) {
            if (meta.txid != val.txid) retained_keys.push_back(key);
            continue;
        }

        // Blocks can arrive out of order; the shared blob must keep the newest
        // observed retention deadline even when its metadata txid is refreshed.
        const int64_t median_time = source == PoDAFlushSource::Block && have_metadata ?
            std::max(meta.nMedianTime, val.nMedianTime) : val.nMedianTime;
        cache_updates.try_emplace(key, val.txid, have_metadata ? meta.nSize : val.nSize, median_time);
        if (source == PoDAFlushSource::Block) {
            retained_keys.push_back(key);
        } else if (!have_blob) {
            owner_updates.emplace(key, val.txid);
        }
    }
    if (batchblob.SizeEstimate() > 0 && !pnevmdatablobdb->WriteBatch(batchblob)) {
        throw dbwrapper_error("Failed to write NEVM blob data");
    }
    for (const auto& [key, meta] : cache_updates) {
        const auto cached = mapCache.find(key);
        if (cached != mapCache.end()) cached->second = meta;
    }
    for (const auto& key : retained_keys) m_mempool_owners.erase(key);
    mapCache.merge(cache_updates);
    m_mempool_owners.merge(owner_updates);
}
bool CNEVMDataDB::FlushCacheToDisk(const int64_t nMedianTime, bool fSync)
{
    LOCK(cs_cache);
    if (mapCache.empty() && !fTestNet) return true;

    CDBBatch batch(*this);
    CDBBatch batchblob(*pnevmdatablobdb);
    NEVMDataVec pruned_keys;
    // only prune on testnet flush, mainnet relies only on CL
    if (fTestNet) {
        if (!PruneToBatch(batch, batchblob, nMedianTime, pruned_keys)) {
            LogPrint(BCLog::SYS, "Error: Could not prune nevm blobs\n");
            return false;
        }
    }
    for (const auto& [key, val] : mapCache) {
        if (fTestNet && nMedianTime > val.nMedianTime + NEVM_DATA_EXPIRE_TIME) continue;
        batch.Write(key, val);
    }
    if (!mapCache.empty()) {
        LogPrint(BCLog::SYS, "Flushing cache to disk, storing %d nevm blobs\n", mapCache.size());
    }
    // Keep metadata indexed until payload deletion succeeds, so interrupted
    // cleanup can be retried without an unindexed payload leak.
    if (batchblob.SizeEstimate() > 0 && !pnevmdatablobdb->WriteBatch(batchblob, fSync)) return false;
    if (!WriteBatch(batch, fSync)) return false;
    mapCache.clear();
    for (const auto& key : pruned_keys) m_mempool_owners.erase(key);
    return true;
}
bool CNEVMDataDB::FlushErase(const NEVMDataVec& vecDataKeys)
{
    LOCK(cs_cache);
    if (vecDataKeys.empty()) return true;

    CDBBatch batch(*this);
    for (const auto& key : vecDataKeys) {
        batch.Erase(key);
    }
    if (!pnevmdatablobdb->FlushErase(vecDataKeys)) return false;
    if (!WriteBatch(batch, true)) return false;
    for (const auto& key : vecDataKeys) {
        mapCache.erase(key);
        m_mempool_owners.erase(key);
    }
    LogPrint(BCLog::SYS, "Flushing, erasing %d nevm blob keys\n", vecDataKeys.size());
    return true;
}
bool CNEVMDataDB::FlushMempoolErase(const std::vector<uint8_t>& vchVersionHash, const uint256& txid)
{
    LOCK(cs_cache);
    const auto owner = m_mempool_owners.find(vchVersionHash);
    if (owner == m_mempool_owners.end() || owner->second != txid) return true;

    MapPoDAPayloadMeta meta;
    const auto cached = mapCache.find(vchVersionHash);
    if (cached != mapCache.end()) {
        meta = cached->second;
    } else if (!Read(vchVersionHash, meta)) {
        return true;
    }
    if (meta.txid != txid) return true;

    CDBBatch batch(*this);
    batch.Erase(vchVersionHash);
    if (!pnevmdatablobdb->FlushErase({vchVersionHash})) return false;
    if (!WriteBatch(batch, true)) return false;
    mapCache.erase(vchVersionHash);
    m_mempool_owners.erase(vchVersionHash);
    return true;
}

void CNEVMDataDB::ReleaseMempoolOwner(const std::vector<uint8_t>& version_hash, const uint256& txid)
{
    LOCK(cs_cache);
    const auto owner = m_mempool_owners.find(version_hash);
    if (owner != m_mempool_owners.end() && owner->second == txid) m_mempool_owners.erase(owner);
}

bool CNEVMDataBlobDB::FlushErase(const NEVMDataVec &vecDataKeys) {
    CDBBatch batch(*this);    
    for (const auto &key : vecDataKeys) {
        batch.Erase(key);
    }
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
    return Read(vchVersionHash, meta);
}
const PoDAMAPMemory& CNEVMDataDB::GetCache() const {
    AssertLockHeld(cs_cache);
    return mapCache;
}
bool CNEVMDataDB::PruneToBatch(
    CDBBatch& batch,
    CDBBatch& batchblob,
    const int64_t nMedianTime,
    NEVMDataVec& pruned_keys)
{
    AssertLockHeld(cs_cache);
    int nCount = 0;
    for (const auto& [key, meta] : mapCache) {
        if (nMedianTime > meta.nMedianTime + NEVM_DATA_EXPIRE_TIME) {
            batch.Erase(key);
            batchblob.Erase(key);
            pruned_keys.push_back(key);
            ++nCount;
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
            // Cached block refreshes supersede older persisted retention times.
            if (mapCache.count(vchVersionHash) != 0) {
                pcursor->Next();
                continue;
            }
            if (pcursor->GetValue(meta)) {
                bool isExpired = nMedianTime > (meta.nMedianTime + NEVM_DATA_EXPIRE_TIME);
                if (isExpired) {
                    batch.Erase(vchVersionHash);
                    batchblob.Erase(vchVersionHash);
                    pruned_keys.push_back(vchVersionHash);
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

bool CNEVMDataDB::PruneStandalone(const int64_t nMedianTime, bool fSync)
{
    LOCK(cs_cache);
    CDBBatch batch(*this);
    CDBBatch batchblob(*pnevmdatablobdb);
    NEVMDataVec pruned_keys;
    if (!PruneToBatch(batch, batchblob, nMedianTime, pruned_keys)) {
        return false;
    }
    if (!pnevmdatablobdb->WriteBatch(batchblob, fSync)) return false;
    if (!WriteBatch(batch, fSync)) return false;
    for (const auto& key : pruned_keys) {
        mapCache.erase(key);
        m_mempool_owners.erase(key);
    }
    return true;
}
