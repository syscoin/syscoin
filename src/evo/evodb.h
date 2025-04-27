// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_EVO_EVODB_H
#define SYSCOIN_EVO_EVODB_H

#include <dbwrapper.h>
#include <sync.h>
#include <uint256.h>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <utility>
#include <logging.h>

template <typename K, typename V, typename Hasher = std::hash<K>>
class CEvoDB : public CDBWrapper {
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator, Hasher> mapCache;
    std::list<std::pair<K, V>> fifoList;
    std::unordered_set<K, Hasher> setEraseCache;
    size_t maxCacheSize{0};
    DBParams m_db_params;
    bool bFlushOnNextRead{false};
public:
    mutable RecursiveMutex cs;
    using CDBWrapper::CDBWrapper;
    explicit CEvoDB(const DBParams &db_params, size_t maxCacheSizeIn) : CDBWrapper(db_params), maxCacheSize(maxCacheSizeIn), m_db_params(db_params) {
    }
    ~CEvoDB() {
        FlushCacheToDisk();
    }
    bool IsCacheFull() const {
        LOCK(cs);
        return maxCacheSize > 0 && (mapCache.size()+setEraseCache.size()) >= maxCacheSize;
    }
    DBParams GetDBParams() const {
        return m_db_params;
    }
    bool ReadCache(const K& key, V& value) {
        LOCK(cs);
        if(bFlushOnNextRead) {
            bFlushOnNextRead = false;
            LogPrint(BCLog::SYS, "Evodb::ReadCache flushing cache before read\n");
            FlushCacheToDisk();
        }
        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            value = it->second->second;
            return true;
        }
        return Read(key, value);
    }
    std::unordered_map<K, V, Hasher> GetMapCacheCopy() {
        LOCK(cs);
        if(bFlushOnNextRead) {
            bFlushOnNextRead = false;
            LogPrint(BCLog::SYS, "Evodb::ReadCache flushing cache before read\n");
            FlushCacheToDisk();
        }
        std::unordered_map<K, V, Hasher> cacheCopy;
        for (const auto& [key, it] : mapCache) {
            cacheCopy[key] = it->second;
        }
        return cacheCopy;
    }

    std::unordered_set<K, Hasher> GetEraseCacheCopy() const {
        LOCK(cs);
        return setEraseCache;
    }

    void RestoreCaches(const std::unordered_map<K, V, Hasher>& mapCacheCopy, const std::unordered_set<K, Hasher>& eraseCacheCopy) {
        LOCK(cs);
        for (const auto& [key, value] : mapCacheCopy) {
            WriteCache(key, value);
        }
        setEraseCache = eraseCacheCopy;
    }

    void WriteCache(const K& key, V&& value) {
        LOCK(cs);
        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            fifoList.erase(it->second);
            mapCache.erase(it);
        }
        fifoList.emplace_back(key, std::move(value));
        mapCache[key] = --fifoList.end();
        setEraseCache.erase(key);

        if (maxCacheSize > 0 && mapCache.size() > maxCacheSize) {
            auto oldest = fifoList.front();
            fifoList.pop_front();
            mapCache.erase(oldest.first);
        }
    }

    void WriteCache(const K& key, const V& value) {
        LOCK(cs);
        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            fifoList.erase(it->second);
            mapCache.erase(it);
        }
        fifoList.emplace_back(key, value);
        mapCache[key] = --fifoList.end();
        setEraseCache.erase(key);

        if (maxCacheSize > 0 && mapCache.size() > maxCacheSize) {
            auto oldest = fifoList.front();
            fifoList.pop_front();
            mapCache.erase(oldest.first);
        }
    }

    bool ExistsCache(const K& key) {
        LOCK(cs);
        if(bFlushOnNextRead) {
            bFlushOnNextRead = false;
            LogPrint(BCLog::SYS, "Evodb::ReadCache flushing cache before read\n");
            FlushCacheToDisk();
        }
        return (mapCache.find(key) != mapCache.end() || Exists(key));
    }

    void EraseCache(const K& key) {
        LOCK(cs);
        bFlushOnNextRead = true;
        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            fifoList.erase(it->second);
            mapCache.erase(it);
        }
        setEraseCache.insert(key);
    }

    bool FlushCacheToDisk() {
        LOCK(cs);

        // If there is nothing to flush, we can return true early.
        if (mapCache.empty() && setEraseCache.empty()) {
            return true;
        }

        // Prepare the batch with our pending writes + erases.
        CDBBatch batch(*this);
        for (const auto& [key, it] : mapCache) {
            batch.Write(key, it->second);
        }
        for (const auto& key : setEraseCache) {
            batch.Erase(key);
        }

        // Attempt to write the batch. If it fails, do NOT clear the caches.
        bool res = WriteBatch(batch, true);
        if (res) {
            LogPrint(BCLog::SYS, "Flushing cache (%s) to disk, storing %d items, erasing %d items\n",
                    GetName(), mapCache.size(), setEraseCache.size());
            // Only clear our in-memory structures on success
            mapCache.clear();
            fifoList.clear();
            setEraseCache.clear();
        }

        return res;
    }

    int64_t CountPersistedEntries() {
        try {
            std::unique_ptr<CDBIterator> pcursor(NewIterator());
            if (!pcursor) {
                 LogPrint(BCLog::SYS, "CEvoDB::%s -- Failed to create DB iterator\n", __func__);
                 return -1; // Indicate error
            }
            int64_t count = 0;
            // We only need to iterate keys, values are not needed for count
            pcursor->SeekToFirst();
            while (pcursor->Valid()) {
                count++;
                pcursor->Next();
            }
            return count;
        } catch (const std::exception& e) {
             LogPrint(BCLog::SYS, "CEvoDB::%s -- Exception during iteration: %s\n", __func__, e.what());
            return -1; // Indicate error
        } catch (...) {
             LogPrint(BCLog::SYS, "CEvoDB::%s -- Unknown exception during iteration\n", __func__);
            return -1; // Indicate error
        }
    }
    size_t GetReadWriteCacheSize() {
        return mapCache.size();
    }
    size_t GetEraseCacheSize() {
        return setEraseCache.size();
    }
    // Getter for testing purposes
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator, Hasher> GetMapCache() const {
        return mapCache;
    }

    std::list<std::pair<K, V>> GetFifoList() const {
        return fifoList;
    }

};

#endif // SYSCOIN_EVO_EVODB_H
