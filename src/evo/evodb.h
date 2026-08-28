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
#include <vector>
#include <logging.h>

template <typename K, typename V, typename Hasher = std::hash<K>>
class CEvoDB : public CDBWrapper {
    struct ValueWithTrailingByteForTesting {
        V value;
        uint8_t trailing{0};

        SERIALIZE_METHODS(ValueWithTrailingByteForTesting, obj)
        {
            READWRITE(obj.value, obj.trailing);
        }
    };
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator, Hasher> mapCache;
    std::list<std::pair<K, V>> fifoList;
    std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator, Hasher> mapReadCache;
    std::list<std::pair<K, V>> readFifoList;
    std::unordered_set<K, Hasher> setEraseCache;
    size_t maxCacheSize{0};
    size_t maxReadCacheSize{0};
    DBParams m_db_params;
    bool bFlushOnNextRead{false};
    // SYSCOIN: Exercise retry safety at the exact batch-publication seam
    // without changing CDBWrapper's production exception contract.
    bool m_fail_next_flush_batch_for_testing{false};
    bool m_fail_next_write_through_for_testing{false};
    bool m_fail_next_sync_write_through_for_testing{false};
public:
    enum class ExactDiskReadResult : uint8_t {
        NOT_FOUND = 0,
        FOUND,
        BLOCKED,
    };

    mutable RecursiveMutex cs;
    using CDBWrapper::CDBWrapper;
    explicit CEvoDB(const DBParams &db_params, size_t maxCacheSizeIn, size_t maxReadCacheSizeIn = 0)
        : CDBWrapper(db_params),
          maxCacheSize(maxCacheSizeIn),
          maxReadCacheSize(maxReadCacheSizeIn),
          m_db_params(db_params)
    {
    }
    ~CEvoDB() {
        FlushCacheToDisk();
    }
private:
    bool WriteFlushBatch(CDBBatch& batch, bool fSync)
    {
        if (m_fail_next_flush_batch_for_testing) {
            m_fail_next_flush_batch_for_testing = false;
            throw dbwrapper_error{"injected EvoDB flush-batch failure"};
        }
        return WriteBatch(batch, fSync);
    }

    void TrimReadCache()
    {
        while (maxReadCacheSize == 0 ? !readFifoList.empty() : readFifoList.size() > maxReadCacheSize) {
            mapReadCache.erase(readFifoList.front().first);
            readFifoList.pop_front();
        }
    }

    void EraseReadCache(const K& key)
    {
        auto it = mapReadCache.find(key);
        if (it == mapReadCache.end()) {
            return;
        }
        readFifoList.erase(it->second);
        mapReadCache.erase(it);
    }

    void WriteReadCache(const K& key, const V& value)
    {
        if (maxReadCacheSize == 0) {
            return;
        }
        EraseReadCache(key);
        readFifoList.emplace_back(key, value);
        mapReadCache[key] = --readFifoList.end();
        TrimReadCache();
    }

    void TouchReadCache(const typename std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator, Hasher>::iterator& it)
    {
        readFifoList.splice(readFifoList.end(), readFifoList, it->second);
    }
public:
    bool IsCacheFull() const {
        LOCK(cs);
        return maxCacheSize > 0 && (mapCache.size()+setEraseCache.size()) >= maxCacheSize;
    }
    DBParams GetDBParams() const {
        return m_db_params;
    }
    void SetReadCacheSize(size_t maxReadCacheSizeIn)
    {
        LOCK(cs);
        maxReadCacheSize = maxReadCacheSizeIn;
        TrimReadCache();
    }
    size_t GetReadCacheSize() const
    {
        LOCK(cs);
        return mapReadCache.size();
    }


    bool ReadCache(const K& key, V& value) {
        LOCK(cs);
        if(bFlushOnNextRead) {
            LogPrint(BCLog::SYS, "Evodb::ReadCache flushing cache before read\n");
            // SYSCOIN: Keep the retry armed until every tombstone is durable;
            // otherwise a failed flush can expose the value being erased.
            if (!FlushCacheToDisk()) return false;
            bFlushOnNextRead = false;
        }
        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            value = it->second->second;
            return true;
        }
        auto it_read = mapReadCache.find(key);
        if (it_read != mapReadCache.end()) {
            value = it_read->second->second;
            TouchReadCache(it_read);
            return true;
        }
        if (!Read(key, value)) {
            return false;
        }
        WriteReadCache(key, value);
        return true;
    }

    // SYSCOIN: Destructive GC derives its durable trust boundary from the
    // physical record, not a cache entry that could hide trailing corruption.
    ExactDiskReadResult ReadExactDiskForGC(const K& key, V& value) {
        LOCK(cs);
        if (mapCache.contains(key) || setEraseCache.contains(key)) {
            return ExactDiskReadResult::BLOCKED;
        }
        std::unique_ptr<CDBIterator> cursor{NewIterator()};
        if (!cursor) return ExactDiskReadResult::BLOCKED;
        cursor->Seek(key);
        if (!cursor->Valid()) {
            cursor->CheckStatus();
            return ExactDiskReadResult::NOT_FOUND;
        }
        K found_key;
        if (!cursor->GetKeyExact(found_key)) {
            return ExactDiskReadResult::BLOCKED;
        }
        if (found_key != key) return ExactDiskReadResult::NOT_FOUND;
        return cursor->GetValueExact(value)
            ? ExactDiskReadResult::FOUND
            : ExactDiskReadResult::BLOCKED;
    }

    // SYSCOIN: Exercise the exact-value decoder against physical trailing
    // bytes without changing the production serialization type.
    bool AppendTrailingValueByteForTesting(const K& key) {
        LOCK(cs);
        if (mapCache.contains(key) || setEraseCache.contains(key)) {
            return false;
        }
        V value;
        if (!CDBWrapper::Read(key, value) ||
            !CDBWrapper::Write(
                key, ValueWithTrailingByteForTesting{value, 0xa5},
                /*fSync=*/true)) {
            return false;
        }
        EraseReadCache(key);
        return true;
    }

    bool RewriteExactValueForTesting(const K& key) {
        LOCK(cs);
        if (mapCache.contains(key) || setEraseCache.contains(key)) {
            return false;
        }
        V value;
        if (!CDBWrapper::Read(key, value) ||
            !CDBWrapper::Write(key, value, /*fSync=*/true)) {
            return false;
        }
        EraseReadCache(key);
        return true;
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
        WriteReadCache(key, fifoList.back().second);
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
        WriteReadCache(key, fifoList.back().second);
        setEraseCache.erase(key);

        if (maxCacheSize > 0 && mapCache.size() > maxCacheSize) {
            auto oldest = fifoList.front();
            fifoList.pop_front();
            mapCache.erase(oldest.first);
        }
    }

    // SYSCOIN: Persist migration anchors and similarly sparse consensus
    // records immediately so bounded dirty-FIFO eviction cannot remove their
    // only durable copy during IBD. Keep only the read-cache copy afterward.
    bool WriteThrough(const K& key, const V& value, bool fSync = true) {
        LOCK(cs);
        if (m_fail_next_write_through_for_testing) {
            m_fail_next_write_through_for_testing = false;
            throw dbwrapper_error{"injected EvoDB write-through failure"};
        }
        if (fSync && m_fail_next_sync_write_through_for_testing) {
            m_fail_next_sync_write_through_for_testing = false;
            throw dbwrapper_error{
                "injected synchronous EvoDB write-through failure"};
        }
        if (!Write(key, value, fSync)) return false;

        auto it = mapCache.find(key);
        if (it != mapCache.end()) {
            fifoList.erase(it->second);
            mapCache.erase(it);
        }
        WriteReadCache(key, value);
        setEraseCache.erase(key);
        return true;
    }

    bool ExistsCache(const K& key) {
        LOCK(cs);
        if(bFlushOnNextRead) {
            LogPrint(BCLog::SYS, "Evodb::ReadCache flushing cache before read\n");
            // SYSCOIN: Existence checks obey the same tombstone durability
            // barrier as reads and retry after a transient batch failure.
            if (!FlushCacheToDisk()) return false;
            bFlushOnNextRead = false;
        }
        auto it_read = mapReadCache.find(key);
        if (it_read != mapReadCache.end()) {
            TouchReadCache(it_read);
            return true;
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
        EraseReadCache(key);
        setEraseCache.insert(key);
    }

    bool FlushCacheToDisk(std::size_t CHUNK_ITEMS = 256, bool fSync = true)
    {
        LOCK(cs);
        if (mapCache.empty() && setEraseCache.empty()) {
            if (!fSync) return true;

            // SYSCOIN: WriteThrough(..., false) records are already outside the
            // dirty FIFO, but a later consensus marker can still require an
            // ordering barrier for their LevelDB WAL. An empty synchronous
            // batch supplies that barrier through the same retryable seam as a
            // non-empty flush.
            CDBBatch barrier(*this);
            return WriteFlushBatch(barrier, /*fSync=*/true);
        }

        const std::size_t chunk_items{CHUNK_ITEMS == 0 ? 1 : CHUNK_ITEMS};
        std::size_t count = 0;

        // SYSCOIN: A failed LevelDB batch must leave its entire dirty chunk
        // retryable. Remove entries only after that exact batch is committed;
        // earlier successful chunks are already durable and may be released.
        while (!fifoList.empty()) {
            CDBBatch batch(*this);
            std::size_t staged{0};
            for (auto it = fifoList.cbegin();
                 it != fifoList.cend() && staged < chunk_items;
                 ++it, ++staged) {
                batch.Write(it->first, it->second);
            }
            if (!WriteFlushBatch(batch, fSync)) return false;
            for (std::size_t committed{0}; committed < staged; ++committed) {
                mapCache.erase(fifoList.front().first);
                fifoList.pop_front();
            }
            count += staged;
        }

        // SYSCOIN: Apply the same post-commit removal rule to tombstones so a
        // failed erase batch cannot resurrect data after restart.
        while (!setEraseCache.empty()) {
            CDBBatch batch(*this);
            std::vector<K> staged_keys;
            staged_keys.reserve(setEraseCache.size() < chunk_items
                                    ? setEraseCache.size()
                                    : chunk_items);
            for (auto it = setEraseCache.cbegin();
                 it != setEraseCache.cend() && staged_keys.size() < chunk_items;
                 ++it) {
                batch.Erase(*it);
                staged_keys.emplace_back(*it);
            }
            if (!WriteFlushBatch(batch, fSync)) return false;
            for (const auto& key : staged_keys) {
                setEraseCache.erase(key);
            }
            count += staged_keys.size();
        }

        LogPrint(BCLog::SYS,
                "Flushed %zu items to disk (%s) in %zu-item chunks\n",
                count, GetName().c_str(), chunk_items);
        return true;
    }

    // SYSCOIN: Tests inject a one-shot exception at the same seam used by
    // real LevelDB failures and then verify that the staged chunk can retry.
    void FailNextFlushBatchForTesting()
    {
        LOCK(cs);
        m_fail_next_flush_batch_for_testing = true;
    }

    // SYSCOIN: This one-shot seam verifies that consensus callers classify a
    // real WriteThrough exception as local I/O failure rather than invalidity.
    void FailNextWriteThroughForTesting()
    {
        LOCK(cs);
        m_fail_next_write_through_for_testing = true;
    }

    // SYSCOIN: Distinguish async journal publication from an accidental
    // per-record fsync without exposing LevelDB internals to focused tests.
    void FailNextSynchronousWriteThroughForTesting()
    {
        LOCK(cs);
        m_fail_next_sync_write_through_for_testing = true;
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
        LOCK(cs);
        return mapCache.size();
    }
    size_t GetEraseCacheSize() {
        LOCK(cs);
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
