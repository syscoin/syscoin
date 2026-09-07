// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dbwrapper.h>
#include <primitives/transaction.h>
#include <services/nevmconsensus.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace {
struct LegacyPoDAMetadata
{
    uint256 txid;
    uint32_t size;
    int64_t median_time;

    SERIALIZE_METHODS(LegacyPoDAMetadata, obj) { READWRITE(obj.txid, obj.size, obj.median_time); }
};

struct PoDAOwnershipSetup : BasicTestingSetup
{
    const bool m_original_testnet{fTestNet};

    PoDAOwnershipSetup()
    {
        fTestNet = false;
        Open(/*memory_only=*/true, /*wipe_data=*/true);
    }

    ~PoDAOwnershipSetup() { fTestNet = m_original_testnet; }

    void Open(bool memory_only, bool wipe_data)
    {
        pnevmdatadb.reset();
        pnevmdatablobdb.reset();
        pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
            .path = m_path_root / "ownership_metadata",
            .cache_bytes = size_t{1 << 20},
            .memory_only = memory_only,
            .wipe_data = wipe_data});
        pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
            .path = m_path_root / "ownership_payloads",
            .cache_bytes = size_t{1 << 20},
            .memory_only = memory_only,
            .wipe_data = wipe_data});
    }

    void Store(const std::vector<uint8_t>& version_hash, const uint256& txid,
               int64_t median_time, PoDAFlushSource source, uint32_t size = 4)
    {
        MapPoDAPayloadMeta meta{txid, size, median_time};
        meta.vchNEVMData = std::make_shared<const std::vector<uint8_t>>(size, uint8_t{1});
        pnevmdatadb->FlushDataToCache({{version_hash, meta}}, source);
    }

    void StoreMetadataOnly(const std::vector<uint8_t>& version_hash, const uint256& txid,
                           int64_t median_time, PoDAFlushSource source, bool empty_payload = false)
    {
        MapPoDAPayloadMeta meta{txid, 0, median_time};
        if (empty_payload) meta.vchNEVMData = std::make_shared<const std::vector<uint8_t>>();
        pnevmdatadb->FlushDataToCache({{version_hash, meta}}, source);
    }

    void CheckMetadata(const std::vector<uint8_t>& version_hash, const uint256& txid,
                       int64_t median_time, uint32_t size = 4, bool expect_blob = true)
    {
        MapPoDAPayloadMeta meta;
        BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
        BOOST_CHECK(meta.txid == txid);
        BOOST_CHECK_EQUAL(meta.nSize, size);
        BOOST_CHECK_EQUAL(meta.nMedianTime, median_time);
        BOOST_CHECK_EQUAL(pnevmdatablobdb->Exists(version_hash), expect_blob);
    }

    void CheckReinsertedLegacyIsRetained(const std::vector<uint8_t>& version_hash, const uint256& txid)
    {
        BOOST_REQUIRE(pnevmdatadb->Write(version_hash, LegacyPoDAMetadata{txid, 4, 3000}, true));
        BOOST_REQUIRE(pnevmdatablobdb->Write(version_hash, std::vector<uint8_t>(4, 1), true));
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(version_hash, txid));
        CheckMetadata(version_hash, txid, 3000);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(nevm_ownership_tests, PoDAOwnershipSetup)

BOOST_AUTO_TEST_CASE(block_promotion_retains_same_and_different_transaction_owners)
{
    const uint256 mempool_txid{uint256S("01")};
    uint8_t seed{0};
    for (bool flush_mempool : {false, true}) {
        for (bool flush_block : {false, true}) {
            for (bool same_txid : {false, true}) {
                const std::vector<uint8_t> key(32, ++seed);
                const uint256 block_txid{same_txid ? mempool_txid : uint256S("02")};
                Store(key, mempool_txid, 1000, PoDAFlushSource::Mempool);
                if (flush_mempool) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));

                Store(key, block_txid, 2000, PoDAFlushSource::Block);
                if (flush_block) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, mempool_txid));
                CheckMetadata(key, block_txid, 2000);

                Store(key, block_txid, 3000, PoDAFlushSource::Mempool);
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, block_txid));
                CheckMetadata(key, block_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(3000));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(mempool_cleanup_requires_matching_exclusive_owner)
{
    const uint256 owner{uint256S("01")};
    uint8_t seed{0};
    for (bool flush : {false, true}) {
        const std::vector<uint8_t> key(32, ++seed);
        Store(key, owner, 1000, PoDAFlushSource::Mempool);
        if (flush) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, uint256S("02")));
        CheckMetadata(key, owner, 1000);
        Store(key, owner, 2000, PoDAFlushSource::Mempool);
        CheckMetadata(key, owner, 1000);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, owner));
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
    }

    const std::vector<uint8_t> block_key(32, 3);
    Store(block_key, owner, 1000, PoDAFlushSource::Block);
    Store(block_key, owner, 2000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(block_key, owner));
    CheckMetadata(block_key, owner, 1000);
}

BOOST_AUTO_TEST_CASE(owner_release_requires_the_matching_transaction)
{
    const uint256 owner{uint256S("01")};
    uint8_t seed{0};
    for (bool flush_first : {false, true}) {
        const std::vector<uint8_t> key(32, ++seed);
        Store(key, owner, 1000, PoDAFlushSource::Mempool);
        if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        pnevmdatadb->ReleaseMempoolOwner(key, uint256S("02"));
        pnevmdatadb->ReleaseMempoolOwner(key, uint256S("02"));
        CheckMetadata(key, owner, 1000);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, owner));
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
        pnevmdatadb->ReleaseMempoolOwner(key, owner);
    }
}

BOOST_AUTO_TEST_CASE(owner_release_preserves_cached_and_flushed_data)
{
    const uint256 owner{uint256S("01")};
    uint8_t seed{0};
    for (bool flush_first : {false, true}) {
        const std::vector<uint8_t> key(32, ++seed);
        Store(key, owner, 1000, PoDAFlushSource::Mempool);
        if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        pnevmdatadb->ReleaseMempoolOwner(key, owner);
        CheckMetadata(key, owner, 1000);
        BOOST_CHECK_EQUAL(pnevmdatadb->Exists(key), flush_first);
        {
            LOCK(pnevmdatadb->cs_cache);
            BOOST_CHECK_EQUAL(pnevmdatadb->GetCache().count(key), flush_first ? 0 : 1);
        }
        std::vector<uint8_t> payload;
        BOOST_REQUIRE(pnevmdatablobdb->Read(key, payload));
        BOOST_CHECK(payload == std::vector<uint8_t>(4, 1));

        pnevmdatadb->ReleaseMempoolOwner(key, owner);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, owner));
        CheckMetadata(key, owner, 1000);
        BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, owner));
        CheckMetadata(key, owner, 1000);
    }
}

BOOST_AUTO_TEST_CASE(repeated_owner_release_cannot_reclaim_a_shared_reference)
{
    const uint256 first_txid{uint256S("01")};
    const uint256 second_txid{uint256S("02")};
    uint8_t seed{0};
    for (bool flush_first : {false, true}) {
        const std::vector<uint8_t> key(32, ++seed);
        Store(key, first_txid, 1000, PoDAFlushSource::Mempool);
        if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        pnevmdatadb->ReleaseMempoolOwner(key, first_txid);
        StoreMetadataOnly(key, second_txid, 2000, PoDAFlushSource::Mempool);
        pnevmdatadb->ReleaseMempoolOwner(key, first_txid);
        pnevmdatadb->ReleaseMempoolOwner(key, second_txid);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_txid));
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, second_txid));
        CheckMetadata(key, first_txid, 1000);
        BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        Store(key, first_txid, 3000, PoDAFlushSource::Mempool);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_txid));
        CheckMetadata(key, first_txid, 1000);
    }
}

BOOST_AUTO_TEST_CASE(metadata_only_blocks_retain_known_payloads_and_sizes)
{
    const uint256 mempool_txid{uint256S("01")};
    uint8_t seed{0};
    for (bool flush_first : {false, true}) {
        for (bool same_txid : {false, true}) {
            for (bool empty_payload : {false, true}) {
                const std::vector<uint8_t> key(32, ++seed);
                const uint256 block_txid{same_txid ? mempool_txid : uint256S("02")};
                Store(key, mempool_txid, 1000, PoDAFlushSource::Mempool);
                if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
                StoreMetadataOnly(key, block_txid, 2000, PoDAFlushSource::Block, empty_payload);
                StoreMetadataOnly(key, block_txid, 1500, PoDAFlushSource::Block, empty_payload);
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, mempool_txid));
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, block_txid));
                CheckMetadata(key, block_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
                CheckMetadata(key, block_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));
                CheckMetadata(key, block_txid, 2000);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(metadata_only_mempool_references_distinguish_shared_ownership)
{
    const uint256 first_txid{uint256S("01")};
    uint8_t seed{0};
    for (bool flush_first : {false, true}) {
        for (bool shared : {false, true}) {
            for (bool empty_payload : {false, true}) {
                const std::vector<uint8_t> key(32, ++seed);
                const uint256 observed_txid{shared ? uint256S("02") : first_txid};
                Store(key, first_txid, 1000, PoDAFlushSource::Mempool);
                if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
                StoreMetadataOnly(key, observed_txid, 2000, PoDAFlushSource::Mempool, empty_payload);
                CheckMetadata(key, first_txid, 1000);
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_txid));
                if (shared) {
                    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, observed_txid));
                    CheckMetadata(key, first_txid, 1000);
                    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
                    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_txid));
                    CheckMetadata(key, first_txid, 1000);
                } else {
                    BOOST_CHECK(!pnevmdatadb->BlobExists(key));
                    BOOST_CHECK(!pnevmdatablobdb->Exists(key));
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(metadata_only_observations_do_not_fabricate_missing_payloads)
{
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> unknown_key(32, 1);
    StoreMetadataOnly(unknown_key, txid, 1000, PoDAFlushSource::Block);
    StoreMetadataOnly(unknown_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_CHECK(!pnevmdatadb->BlobExists(unknown_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(unknown_key));

    const std::vector<uint8_t> orphan_key(32, 2);
    BOOST_REQUIRE(pnevmdatablobdb->Write(orphan_key, std::vector<uint8_t>(4, 1)));
    StoreMetadataOnly(orphan_key, txid, 1000, PoDAFlushSource::Block);
    BOOST_CHECK(!pnevmdatadb->BlobExists(orphan_key));
    BOOST_CHECK(pnevmdatablobdb->Exists(orphan_key));

    const std::vector<uint8_t> missing_key(32, 3);
    Store(missing_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatablobdb->Erase(missing_key));
    StoreMetadataOnly(missing_key, txid, 2000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(missing_key, txid));
    CheckMetadata(missing_key, txid, 2000, /*size=*/4, /*expect_blob=*/false);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));
    CheckMetadata(missing_key, txid, 2000, /*size=*/4, /*expect_blob=*/false);
}

BOOST_AUTO_TEST_CASE(retained_block_expiry_is_monotone_across_timestamp_orders)
{
    const uint256 first_txid{uint256S("01")};
    const uint256 second_txid{uint256S("02")};
    uint8_t seed{0};
    for (bool newer_block_first : {false, true}) {
        for (bool flush_first : {false, true}) {
            for (bool flush_second : {false, true}) {
                const std::vector<uint8_t> key(32, ++seed);
                Store(key, first_txid, newer_block_first ? 2000 : 1000, PoDAFlushSource::Block);
                if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));
                Store(key, second_txid, newer_block_first ? 1000 : 2000, PoDAFlushSource::Block);
                CheckMetadata(key, second_txid, 2000);
                if (flush_second) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));

                Store(key, uint256S("03"), 3000, PoDAFlushSource::Block, /*size=*/3);
                Store(key, second_txid, 4000, PoDAFlushSource::Mempool);
                CheckMetadata(key, second_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
                CheckMetadata(key, second_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->PruneStandalone(2000 + NEVM_DATA_EXPIRE_TIME));
                CheckMetadata(key, second_txid, 2000);
                BOOST_REQUIRE(pnevmdatadb->PruneStandalone(2001 + NEVM_DATA_EXPIRE_TIME));
                BOOST_CHECK(!pnevmdatadb->BlobExists(key));
                BOOST_CHECK(!pnevmdatablobdb->Exists(key));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(retained_block_expiry_uses_newest_cache_time_and_survives_flush)
{
    Open(/*memory_only=*/false, /*wipe_data=*/true);
    const std::vector<uint8_t> key(32, 1);
    const uint256 last_txid{uint256S("03")};
    Store(key, uint256S("01"), 1000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    Store(key, uint256S("02"), 3000, PoDAFlushSource::Block);
    Store(key, last_txid, 2000, PoDAFlushSource::Block);
    CheckMetadata(key, last_txid, 3000);
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(2001 + NEVM_DATA_EXPIRE_TIME));
    CheckMetadata(key, last_txid, 3000);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(3000));

    Open(/*memory_only=*/false, /*wipe_data=*/false);
    CheckMetadata(key, last_txid, 3000);
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(2001 + NEVM_DATA_EXPIRE_TIME));
    CheckMetadata(key, last_txid, 3000);
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(3001 + NEVM_DATA_EXPIRE_TIME));
    BOOST_CHECK(!pnevmdatadb->BlobExists(key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(key));
}

BOOST_AUTO_TEST_CASE(shared_mempool_blobs_revoke_exclusive_cleanup_authority)
{
    const uint256 first_txid{uint256S("01")};
    const uint256 second_txid{uint256S("02")};
    uint8_t seed{0};
    NEVMDataVec shared_keys;
    for (bool flush_first : {false, true}) {
        for (bool flush_shared : {false, true}) {
            for (bool erase_first_owner_first : {false, true}) {
                const std::vector<uint8_t> key(32, ++seed);
                shared_keys.push_back(key);
                Store(key, first_txid, 1000, PoDAFlushSource::Mempool);
                if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
                Store(key, second_txid, 2000, PoDAFlushSource::Mempool);
                CheckMetadata(key, first_txid, 1000);
                if (flush_shared) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));

                const uint256 first_removed{erase_first_owner_first ? first_txid : second_txid};
                const uint256 second_removed{erase_first_owner_first ? second_txid : first_txid};
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_removed));
                CheckMetadata(key, first_txid, 1000);
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, second_removed));
                CheckMetadata(key, first_txid, 1000);

                Store(key, first_txid, 3000, PoDAFlushSource::Mempool);
                BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, first_txid));
                CheckMetadata(key, first_txid, 1000);
            }
        }
    }
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
    for (const auto& key : shared_keys) {
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
    }
}

BOOST_AUTO_TEST_CASE(reopened_metadata_does_not_restore_deletion_authority)
{
    Open(/*memory_only=*/false, /*wipe_data=*/true);
    const std::vector<uint8_t> shared_key(32, 1);
    const std::vector<uint8_t> sole_key(32, 2);
    const uint256 first_txid{uint256S("01")};
    const uint256 second_txid{uint256S("02")};
    Store(shared_key, first_txid, 1000, PoDAFlushSource::Mempool);
    Store(sole_key, first_txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    Store(shared_key, second_txid, 2000, PoDAFlushSource::Mempool);

    Open(/*memory_only=*/false, /*wipe_data=*/false);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(shared_key, first_txid));
    CheckMetadata(shared_key, first_txid, 1000);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(shared_key, second_txid));
    CheckMetadata(shared_key, first_txid, 1000);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(sole_key, first_txid));
    CheckMetadata(sole_key, first_txid, 1000);

    const std::vector<uint8_t> current_session_key(32, 3);
    Store(current_session_key, first_txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(current_session_key, first_txid));
    BOOST_CHECK(!pnevmdatadb->BlobExists(current_session_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(current_session_key));
}

BOOST_AUTO_TEST_CASE(size_mismatch_cannot_promote_or_refresh_metadata)
{
    const uint256 owner{uint256S("01")};
    uint8_t seed{0};
    for (bool flush : {false, true}) {
        const std::vector<uint8_t> key(32, ++seed);
        Store(key, owner, 1000, PoDAFlushSource::Mempool);
        if (flush) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
        Store(key, owner, 2000, PoDAFlushSource::Block, /*size=*/3);
        Store(key, uint256S("02"), 2000, PoDAFlushSource::Mempool, /*size=*/3);
        CheckMetadata(key, owner, 1000);
        BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, owner));
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
    }
}

BOOST_AUTO_TEST_CASE(legacy_metadata_without_owner_remains_retained_after_reopen)
{
    Open(/*memory_only=*/false, /*wipe_data=*/true);
    const std::vector<uint8_t> key(32, 1);
    const uint256 txid{uint256S("01")};
    const LegacyPoDAMetadata legacy{txid, 4, 1000};
    DataStream old_format;
    old_format << legacy;
    DataStream current_format;
    current_format << MapPoDAPayloadMeta{txid, 4, 1000};
    BOOST_CHECK(old_format.str() == current_format.str());
    BOOST_REQUIRE(pnevmdatadb->Write(key, legacy, true));
    BOOST_REQUIRE(pnevmdatablobdb->Write(key, std::vector<uint8_t>(4, 1), true));

    Open(/*memory_only=*/false, /*wipe_data=*/false);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, txid));
    Store(key, txid, 2000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, txid));
    CheckMetadata(key, txid, 1000);

    Store(key, txid, 3000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(3000));
    Open(/*memory_only=*/false, /*wipe_data=*/false);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, txid));
    CheckMetadata(key, txid, 3000);
}

BOOST_AUTO_TEST_CASE(old_format_metadata_refresh_cannot_restore_session_authority)
{
    Open(/*memory_only=*/false, /*wipe_data=*/true);
    const std::vector<uint8_t> key(32, 1);
    const uint256 txid{uint256S("01")};
    Store(key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    // Another session/version may refresh metadata without recording ownership.
    // Reopening must not infer exclusive authority from the unchanged txid.
    BOOST_REQUIRE(pnevmdatadb->Write(key, LegacyPoDAMetadata{txid, 4, 2000}, true));
    Open(/*memory_only=*/false, /*wipe_data=*/false);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, txid));
    Store(key, txid, 3000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(key, txid));
    CheckMetadata(key, txid, 2000);
}

BOOST_AUTO_TEST_CASE(missing_payload_repair_and_orphans_do_not_invent_ownership)
{
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> retained_key(32, 1);
    Store(retained_key, txid, 1000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatablobdb->Erase(retained_key));
    Store(retained_key, txid, 2000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(retained_key, txid));
    CheckMetadata(retained_key, txid, 1000);

    const std::vector<uint8_t> orphan_key(32, 2);
    BOOST_REQUIRE(pnevmdatablobdb->Write(orphan_key, std::vector<uint8_t>(4, 1)));
    Store(orphan_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(orphan_key, txid));
    CheckMetadata(orphan_key, txid, 1000);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));

    const std::vector<uint8_t> mempool_key(32, 3);
    Store(mempool_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatablobdb->Erase(mempool_key));
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(mempool_key, txid));
    BOOST_CHECK(!pnevmdatadb->BlobExists(mempool_key));

    const std::vector<uint8_t> promoted_key(32, 4);
    Store(promoted_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatablobdb->Erase(promoted_key));
    Store(promoted_key, txid, 2000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(promoted_key, txid));
    CheckMetadata(promoted_key, txid, 2000);
}

BOOST_AUTO_TEST_CASE(unreadable_metadata_is_not_new_deletion_authority)
{
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> unreadable_key(32, 2);
    BOOST_REQUIRE(pnevmdatadb->Write(unreadable_key, uint8_t{1}));
    Store(unreadable_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(unreadable_key, txid));
    BOOST_CHECK(pnevmdatadb->Exists(unreadable_key));
    MapPoDAPayloadMeta meta;
    BOOST_CHECK(!pnevmdatadb->GetBlobMetaData(unreadable_key, meta));
}

BOOST_AUTO_TEST_CASE(pruning_and_explicit_erase_retire_session_owners)
{
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> expired_key(32, 1);
    const std::vector<uint8_t> refreshed_key(32, 2);
    const std::vector<uint8_t> pending_key(32, 3);
    const std::vector<uint8_t> erase_key(32, 4);
    Store(expired_key, txid, 1000, PoDAFlushSource::Mempool);
    Store(refreshed_key, txid, 1000, PoDAFlushSource::Mempool);
    Store(erase_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    Store(refreshed_key, txid, 2000, PoDAFlushSource::Block);
    Store(pending_key, txid, 1000, PoDAFlushSource::Mempool);

    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1000 + NEVM_DATA_EXPIRE_TIME));
    CheckMetadata(expired_key, txid, 1000);
    CheckMetadata(pending_key, txid, 1000);
    BOOST_REQUIRE(pnevmdatadb->FlushErase({erase_key}));
    BOOST_CHECK(!pnevmdatadb->BlobExists(erase_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(erase_key));

    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
    for (const auto& key : {expired_key, pending_key}) {
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
    }
    CheckMetadata(refreshed_key, txid, 2000);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2000));
    CheckMetadata(refreshed_key, txid, 2000);

    for (const auto& key : {expired_key, pending_key, erase_key}) {
        CheckReinsertedLegacyIsRetained(key, txid);
    }
}

BOOST_AUTO_TEST_CASE(testnet_flush_prunes_cached_and_flushed_session_owners)
{
    fTestNet = true;
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> persisted_key(32, 1);
    const std::vector<uint8_t> pending_key(32, 2);
    const std::vector<uint8_t> refreshed_key(32, 3);
    Store(persisted_key, txid, 1000, PoDAFlushSource::Mempool);
    Store(refreshed_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    Store(pending_key, txid, 1000, PoDAFlushSource::Mempool);
    Store(refreshed_key, txid, 2000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1001 + NEVM_DATA_EXPIRE_TIME));
    for (const auto& key : {persisted_key, pending_key}) {
        BOOST_CHECK(!pnevmdatadb->BlobExists(key));
        BOOST_CHECK(!pnevmdatablobdb->Exists(key));
    }
    CheckMetadata(refreshed_key, txid, 2000);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(2001 + NEVM_DATA_EXPIRE_TIME));
    BOOST_CHECK(!pnevmdatadb->BlobExists(refreshed_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(refreshed_key));
    for (const auto& key : {persisted_key, pending_key}) {
        CheckReinsertedLegacyIsRetained(key, txid);
    }
}

BOOST_AUTO_TEST_CASE(prune_retry_completes_indexed_missing_payload_cleanup)
{
    const uint256 txid{uint256S("01")};
    uint8_t seed{0};
    for (bool testnet_flush : {false, true}) {
        fTestNet = testnet_flush;
        for (bool flush_first : {false, true}) {
            const std::vector<uint8_t> key(32, ++seed);
            Store(key, txid, 1000, PoDAFlushSource::Mempool);
            if (flush_first) BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
            // This benign intermediate state also occurs after payload cleanup
            // completes but before its metadata erase is committed.
            BOOST_REQUIRE(pnevmdatablobdb->Erase(key, true));
            CheckMetadata(key, txid, 1000, /*size=*/4, /*expect_blob=*/false);
            if (testnet_flush) {
                BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1001 + NEVM_DATA_EXPIRE_TIME));
            } else {
                BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
            }
            BOOST_CHECK(!pnevmdatadb->BlobExists(key));
            BOOST_CHECK(!pnevmdatablobdb->Exists(key));
            CheckReinsertedLegacyIsRetained(key, txid);
        }
    }
}

BOOST_AUTO_TEST_CASE(prune_retry_after_reopen_preserves_a_new_retained_refresh)
{
    Open(/*memory_only=*/false, /*wipe_data=*/true);
    const uint256 txid{uint256S("01")};
    const std::vector<uint8_t> expired_key(32, 1);
    const std::vector<uint8_t> refreshed_key(32, 2);
    Store(expired_key, txid, 1000, PoDAFlushSource::Mempool);
    Store(refreshed_key, txid, 1000, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(1000));
    BOOST_REQUIRE(pnevmdatablobdb->FlushErase({expired_key, refreshed_key}));

    Open(/*memory_only=*/false, /*wipe_data=*/false);
    Store(refreshed_key, txid, 2000, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(1001 + NEVM_DATA_EXPIRE_TIME));
    BOOST_CHECK(!pnevmdatadb->BlobExists(expired_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(expired_key));
    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(refreshed_key, txid));
    CheckMetadata(refreshed_key, txid, 2000);
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(2001 + NEVM_DATA_EXPIRE_TIME));
    BOOST_CHECK(!pnevmdatadb->BlobExists(refreshed_key));
    BOOST_CHECK(!pnevmdatablobdb->Exists(refreshed_key));
}

BOOST_AUTO_TEST_SUITE_END()
