// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <dbwrapper.h>
#include <primitives/transaction.h>
#include <services/assetconsensus.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/hasher.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
uint256 TestHash(uint64_t value)
{
    return ArithToUint256(arith_uint256{value});
}

const uint256& CacheKey(const uint256& key)
{
    return key;
}

const uint256& CacheKey(const NEVMTxRootMap::value_type& entry)
{
    return entry.first;
}

void AddCacheEntry(CDBBatch& batch, const uint256& key)
{
    batch.Write(key, true);
}

void AddCacheEntry(CDBBatch& batch, const NEVMTxRootMap::value_type& entry)
{
    batch.Write(entry.first, entry.second);
}

void CheckStoredEntry(CDBWrapper& db, const uint256& key)
{
    bool marker{false};
    BOOST_REQUIRE(db.Read(key, marker));
    BOOST_CHECK(marker);
}

void CheckStoredEntry(CDBWrapper& db, const NEVMTxRootMap::value_type& entry)
{
    NEVMTxRoot roots;
    BOOST_REQUIRE(db.Read(entry.first, roots));
    BOOST_CHECK(roots.nTxRoot == entry.second.nTxRoot);
    BOOST_CHECK(roots.nReceiptRoot == entry.second.nReceiptRoot);
}

template <typename Cache>
void CheckFailedChunk(const fs::path& path, Cache cache, std::size_t chunk_items,
                      std::size_t failed_chunk, bool throw_error, bool sync)
{
    CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .memory_only = true});
    // Snapshot this container's order; salted hash iteration is not key order.
    const std::vector<typename Cache::value_type> entries(cache.begin(), cache.end());
    std::size_t staged_items{0};
    std::vector<std::size_t> batch_sizes;
    const auto add_entry = [&](CDBBatch& batch, const auto& entry) {
        AddCacheEntry(batch, entry);
        ++staged_items;
    };
    const auto fail_writer = [&](CDBBatch& batch, bool actual_sync) {
        BOOST_CHECK_EQUAL(actual_sync, sync);
        batch_sizes.push_back(staged_items);
        staged_items = 0;
        if (batch_sizes.size() == failed_chunk) {
            if (throw_error) throw dbwrapper_error("local writeback test failure");
            return false;
        }
        return db.WriteBatch(batch, actual_sync);
    };
    const auto flush = [&] {
        return nevm_cache_detail::FlushCache(db, cache, chunk_items, sync, add_entry, fail_writer);
    };
    if (throw_error) {
        BOOST_CHECK_THROW(flush(), dbwrapper_error);
    } else {
        BOOST_CHECK(!flush());
    }

    BOOST_REQUIRE_EQUAL(batch_sizes.size(), failed_chunk);
    const std::size_t written_items = chunk_items * (failed_chunk - 1);
    BOOST_REQUIRE(written_items < entries.size());
    const std::size_t limit = chunk_items == 0 ? entries.size() : chunk_items;
    BOOST_CHECK_EQUAL(batch_sizes.back(), std::min(limit, entries.size() - written_items));
    BOOST_CHECK_EQUAL(cache.size(), entries.size() - written_items);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& key = CacheKey(entries[i]);
        BOOST_CHECK_EQUAL(cache.count(key), i >= written_items ? 1U : 0U);
        BOOST_CHECK_EQUAL(db.Exists(key), i < written_items);
        if (i < written_items) CheckStoredEntry(db, entries[i]);
    }

    std::size_t retry_items{0};
    const auto retry_entry = [&](CDBBatch& batch, const auto& entry) {
        AddCacheEntry(batch, entry);
        ++retry_items;
    };
    const auto retry_writer = [&](CDBBatch& batch, bool actual_sync) {
        BOOST_CHECK_EQUAL(actual_sync, sync);
        return db.WriteBatch(batch, actual_sync);
    };
    BOOST_REQUIRE(nevm_cache_detail::FlushCache(db, cache, chunk_items, sync, retry_entry, retry_writer));
    BOOST_CHECK(cache.empty());
    BOOST_CHECK_EQUAL(retry_items, entries.size() - written_items);
    for (const auto& entry : entries) CheckStoredEntry(db, entry);
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(nevm_cache_writeback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(failed_batches_preserve_pending_entries)
{
    for (const bool sync : {false, true}) {
        for (const bool throw_error : {false, true}) {
            for (const std::size_t chunk_items : {0U, 1U, 2U, 256U}) {
                const std::size_t entry_count = chunk_items == 0 ? 5 : 2 * chunk_items + 1;
                NEVMMintTxSet mints;
                NEVMTxRootMap roots;
                for (std::size_t i = 0; i < entry_count; ++i) {
                    const uint256 key = TestHash(i + 1);
                    mints.insert(key);
                    roots.emplace(key, NEVMTxRoot{TestHash(i + 1000), TestHash(i + 2000)});
                }
                const std::size_t chunk_count = chunk_items == 0 ? 1 : (entry_count + chunk_items - 1) / chunk_items;
                for (std::size_t failed_chunk = 1; failed_chunk <= chunk_count; ++failed_chunk) {
                    BOOST_TEST_CONTEXT("chunk_items=" << chunk_items << ", failed_chunk=" << failed_chunk
                                                     << ", throw=" << throw_error << ", sync=" << sync) {
                        CheckFailedChunk(m_args.GetDataDirBase() / "mint_writeback", mints,
                                         chunk_items, failed_chunk, throw_error, sync);
                        CheckFailedChunk(m_args.GetDataDirBase() / "root_writeback", roots,
                                         chunk_items, failed_chunk, throw_error, sync);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(empty_cache_does_not_write)
{
    CDBWrapper db({.path = m_args.GetDataDirBase() / "empty_writeback", .cache_bytes = 1 << 20, .memory_only = true});
    NEVMMintTxSet mints;
    NEVMTxRootMap roots;
    const auto unexpected_entry = [](CDBBatch&, const auto&) { BOOST_FAIL("empty cache staged an entry"); };
    const auto unexpected_writer = [](CDBBatch&, bool) {
        BOOST_FAIL("empty cache submitted a batch");
        return false;
    };
    for (const std::size_t chunk_items : {0U, 1U, 256U}) {
        BOOST_CHECK(nevm_cache_detail::FlushCache(db, mints, chunk_items, true, unexpected_entry, unexpected_writer));
        BOOST_CHECK(nevm_cache_detail::FlushCache(db, roots, chunk_items, false, unexpected_entry, unexpected_writer));
    }
}

BOOST_AUTO_TEST_CASE(public_cache_flush_preserves_serialization_and_persistence)
{
    const fs::path mint_path = m_args.GetDataDirBase() / "mint_writeback_persistence";
    const fs::path root_path = m_args.GetDataDirBase() / "root_writeback_persistence";
    for (const bool sync : {false, true}) {
        for (const std::size_t chunk_items : {0U, 1U, 2U, 256U}) {
            const std::size_t full_chunk = chunk_items == 0 ? 5 : chunk_items;
            for (const std::size_t entry_count : {std::size_t{0}, std::size_t{1}, full_chunk, full_chunk + 1}) {
                NEVMMintTxSet mints;
                NEVMTxRootMap roots;
                for (std::size_t i = 0; i < entry_count; ++i) {
                    const uint256 key = TestHash(i + 1);
                    mints.insert(key);
                    roots.emplace(key, NEVMTxRoot{TestHash(i + 1000), TestHash(i + 2000)});
                }
                {
                    CNEVMMintedTxDB mint_db({.path = mint_path, .cache_bytes = 1 << 20, .wipe_data = true});
                    CNEVMTxRootsDB root_db({.path = root_path, .cache_bytes = 1 << 20, .wipe_data = true});
                    mint_db.FlushDataToCache(mints);
                    root_db.FlushDataToCache(roots);
                    for (const auto& key : mints) {
                        BOOST_CHECK(mint_db.ExistsTx(key));
                        BOOST_CHECK(!mint_db.Exists(key));
                    }
                    for (const auto& entry : roots) {
                        NEVMTxRoot value;
                        BOOST_REQUIRE(root_db.ReadTxRoots(entry.first, value));
                        BOOST_CHECK(value.nTxRoot == entry.second.nTxRoot);
                        BOOST_CHECK(value.nReceiptRoot == entry.second.nReceiptRoot);
                        BOOST_CHECK(!root_db.Exists(entry.first));
                    }
                    BOOST_REQUIRE(mint_db.FlushCacheToDisk(chunk_items, sync));
                    BOOST_REQUIRE(root_db.FlushCacheToDisk(chunk_items, sync));
                    for (const auto& key : mints) CheckStoredEntry(mint_db, key);
                    for (const auto& entry : roots) CheckStoredEntry(root_db, entry);
                    BOOST_REQUIRE(mint_db.FlushCacheToDisk(chunk_items, sync));
                    BOOST_REQUIRE(root_db.FlushCacheToDisk(chunk_items, sync));
                }
                {
                    CNEVMMintedTxDB mint_db({.path = mint_path, .cache_bytes = 1 << 20});
                    CNEVMTxRootsDB root_db({.path = root_path, .cache_bytes = 1 << 20});
                    for (const auto& key : mints) {
                        BOOST_CHECK(mint_db.ExistsTx(key));
                        CheckStoredEntry(mint_db, key);
                    }
                    for (const auto& entry : roots) {
                        NEVMTxRoot value;
                        BOOST_REQUIRE(root_db.ReadTxRoots(entry.first, value));
                        BOOST_CHECK(value.nTxRoot == entry.second.nTxRoot);
                        BOOST_CHECK(value.nReceiptRoot == entry.second.nReceiptRoot);
                        CheckStoredEntry(root_db, entry);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
