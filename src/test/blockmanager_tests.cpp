// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

using node::BLOCK_SERIALIZATION_HEADER_SIZE;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

// SYSCOIN BEGIN: Inject batch failures in the real transaction-height cache.
namespace {
class FailingBlockIndexDB : public CBlockIndexDB {
public:
    enum class Failure { FALSE_RESULT, THROW_BEFORE, THROW_AFTER };
    using CBlockIndexDB::CBlockIndexDB;
    std::vector<bool> sync_calls;
    std::size_t fail_call{0};
    Failure failure{Failure::THROW_BEFORE};

protected:
    bool WriteCacheBatch(CDBBatch& batch, bool sync) override
    {
        sync_calls.push_back(sync);
        if (sync_calls.size() == fail_call) {
            if (failure == Failure::FALSE_RESULT) return false;
            if (failure == Failure::THROW_AFTER) CDBWrapper::WriteBatch(batch, sync);
            throw dbwrapper_error{"injected transaction-height batch failure"};
        }
        return CDBWrapper::WriteBatch(batch, sync);
    }
};

uint256 IndexKey(uint8_t value)
{
    uint256 key;
    key.begin()[0] = value;
    return key;
}
} // namespace
// SYSCOIN END: Inject batch failures in the real transaction-height cache.

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

// SYSCOIN BEGIN: Retrying inserts and deletions preserves data and batching.
BOOST_AUTO_TEST_CASE(block_index_failed_chunks_remain_retryable)
{
    LOCK(cs_main);
    std::vector<std::pair<uint256, uint32_t>> rows;
    for (uint8_t i = 1; i <= 5; ++i) rows.emplace_back(IndexKey(i), 100 + i);
    for (const std::size_t chunk : {1U, 2U, 100000U, 0U}) {
        const auto batches = chunk == 0 ? 1 : (rows.size() + chunk - 1) / chunk;
        for (std::size_t fail_call = 1; fail_call <= batches; ++fail_call) {
            for (const auto failure : {FailingBlockIndexDB::Failure::FALSE_RESULT,
                                       FailingBlockIndexDB::Failure::THROW_BEFORE,
                                       FailingBlockIndexDB::Failure::THROW_AFTER}) {
                FailingBlockIndexDB db{{.path = m_path_root / "height-chunks", .cache_bytes = 1 << 20, .memory_only = true}};
                db.FlushDataToCache(rows);
                db.fail_call = fail_call;
                db.failure = failure;
                if (failure == FailingBlockIndexDB::Failure::FALSE_RESULT) {
                    BOOST_CHECK(!db.FlushCacheToDisk(200, chunk, /*fSync=*/false));
                } else {
                    BOOST_CHECK_THROW(db.FlushCacheToDisk(200, chunk, /*fSync=*/false), dbwrapper_error);
                }
                for (const auto& [key, expected] : rows) {
                    uint32_t height{0};
                    BOOST_REQUIRE(db.ReadBlockHeight(key, height));
                    BOOST_CHECK_EQUAL(height, expected);
                }
                BOOST_REQUIRE(db.FlushCacheToDisk(200, chunk, /*fSync=*/false));
                // Exactly one failed/unacknowledged batch is repeated.
                BOOST_CHECK_EQUAL(db.sync_calls.size(), batches + 1);
                for (const bool sync : db.sync_calls) BOOST_CHECK(!sync);
                for (const auto& [key, expected] : rows) {
                    uint32_t height{0};
                    BOOST_REQUIRE(db.Read(key, height));
                    BOOST_CHECK_EQUAL(height, expected);
                }
                BOOST_REQUIRE(db.FlushCacheToDisk(200, chunk, /*fSync=*/true));
                BOOST_CHECK_EQUAL(db.sync_calls.size(), batches + 1);
            }
        }
        FailingBlockIndexDB success{{.path = m_path_root / "height-success", .cache_bytes = 1 << 20, .memory_only = true}};
        success.FlushDataToCache(rows);
        BOOST_REQUIRE(success.FlushCacheToDisk(200, chunk, /*fSync=*/false));
        BOOST_CHECK_EQUAL(success.sync_calls.size(), batches);
        for (const bool sync : success.sync_calls) BOOST_CHECK(!sync);
    }
}

BOOST_AUTO_TEST_CASE(block_index_erase_retry_and_latest_put)
{
    LOCK(cs_main);
    const auto disk_key = IndexKey(1), cached_key = IndexKey(2), kept_key = IndexKey(3);
    for (const auto failure : {FailingBlockIndexDB::Failure::FALSE_RESULT,
                               FailingBlockIndexDB::Failure::THROW_BEFORE,
                               FailingBlockIndexDB::Failure::THROW_AFTER}) {
        FailingBlockIndexDB db{{.path = m_path_root / "height-erases", .cache_bytes = 1 << 20, .memory_only = true}};
        BOOST_REQUIRE(db.Write(disk_key, uint32_t{100}));
        db.FlushDataToCache({{cached_key, 101}, {kept_key, 102}});
        db.fail_call = 1;
        db.failure = failure;
        if (failure == FailingBlockIndexDB::Failure::FALSE_RESULT) {
            BOOST_CHECK(!db.FlushErase({{disk_key, 100}, {cached_key, 101}}));
        } else {
            BOOST_CHECK_THROW(db.FlushErase({{disk_key, 100}, {cached_key, 101}}), dbwrapper_error);
        }
        uint32_t height{0};
        BOOST_CHECK(!db.ReadBlockHeight(disk_key, height));
        BOOST_CHECK(!db.ReadBlockHeight(cached_key, height));
        BOOST_REQUIRE(db.ReadBlockHeight(kept_key, height));
        BOOST_CHECK_EQUAL(height, 102U);
        BOOST_REQUIRE(db.FlushCacheToDisk(200, 2, /*fSync=*/false));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 2U);
        BOOST_CHECK(db.sync_calls[0]);
        BOOST_CHECK(db.sync_calls[1]);
        BOOST_CHECK(!db.Exists(disk_key));
        BOOST_CHECK(!db.Exists(cached_key));
        BOOST_REQUIRE(db.Read(kept_key, height));
        BOOST_CHECK_EQUAL(height, 102U);

        db.fail_call = 3;
        db.failure = FailingBlockIndexDB::Failure::THROW_BEFORE;
        BOOST_CHECK_THROW(db.FlushErase({{kept_key, 102}}), dbwrapper_error);
        db.FlushDataToCache({{kept_key, 150}});
        BOOST_REQUIRE(db.ReadBlockHeight(kept_key, height));
        BOOST_CHECK_EQUAL(height, 150U);
        BOOST_REQUIRE(db.FlushCacheToDisk(200, 2, /*fSync=*/false));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 4U);
        BOOST_CHECK(!db.sync_calls.back());
        BOOST_REQUIRE(db.Read(kept_key, height));
        BOOST_CHECK_EQUAL(height, 150U);
        BOOST_REQUIRE(db.FlushErase({{kept_key, 150}}));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 5U);
        BOOST_REQUIRE(db.FlushCacheToDisk(200));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 5U);
    }
}

BOOST_AUTO_TEST_CASE(block_index_pruning_shares_the_first_batch)
{
    LOCK(cs_main);
    const auto newer_key = IndexKey(1), stale_key = IndexKey(2), added_key = IndexKey(3);
    for (const std::size_t fail_call : {0U, 1U, 2U}) {
        FailingBlockIndexDB db{{.path = m_path_root / "height-prune", .cache_bytes = 1 << 20, .memory_only = true}};
        BOOST_REQUIRE(db.Write(newer_key, uint32_t{5}));
        BOOST_REQUIRE(db.Write(stale_key, uint32_t{6}));
        db.FlushDataToCache({{newer_key, 100}, {added_key, 101}});
        db.fail_call = fail_call;
        if (fail_call != 0) {
            BOOST_CHECK_THROW(db.FlushCacheToDisk(MAX_BLOCK_INDEX + 10, 1, /*fSync=*/false), dbwrapper_error);
            uint32_t height{0};
            BOOST_CHECK(!db.ReadBlockHeight(stale_key, height));
            BOOST_REQUIRE(db.ReadBlockHeight(newer_key, height));
            BOOST_CHECK_EQUAL(height, 100U);
        }
        BOOST_REQUIRE(db.FlushCacheToDisk(MAX_BLOCK_INDEX + 10, 1, /*fSync=*/false));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), fail_call == 0 ? 2U : 3U);
        for (const bool sync : db.sync_calls) BOOST_CHECK(!sync);
        BOOST_CHECK(!db.Exists(stale_key));
        uint32_t height{0};
        BOOST_REQUIRE(db.Read(newer_key, height));
        BOOST_CHECK_EQUAL(height, 100U);
        BOOST_REQUIRE(db.Read(added_key, height));
        BOOST_CHECK_EQUAL(height, 101U);
    }
}

BOOST_AUTO_TEST_CASE(block_index_staged_erases_survive_skipped_write)
{
    LOCK(cs_main);
    const auto disk_key = IndexKey(1), cached_key = IndexKey(2);
    FailingBlockIndexDB db{{.path = m_path_root / "height-staged", .cache_bytes = 1 << 20, .memory_only = true}};
    BOOST_REQUIRE(db.Write(disk_key, uint32_t{100}));
    db.FlushDataToCache({{cached_key, 101}});
    // An earlier auxiliary DB may fail before this DB's FlushErase is reached.
    db.EraseCache({{disk_key, 100}, {cached_key, 101}});
    BOOST_CHECK(db.sync_calls.empty());
    uint32_t height{0};
    BOOST_CHECK(!db.ReadBlockHeight(disk_key, height));
    BOOST_CHECK(!db.ReadBlockHeight(cached_key, height));
    BOOST_REQUIRE(db.FlushCacheToDisk(200, 100000, /*fSync=*/false));
    BOOST_REQUIRE_EQUAL(db.sync_calls.size(), 1U);
    BOOST_CHECK(db.sync_calls.back());
    BOOST_CHECK(!db.Exists(disk_key));
    BOOST_CHECK(!db.Exists(cached_key));
}

BOOST_AUTO_TEST_CASE(block_index_erase_only_retry_survives_reopen)
{
    LOCK(cs_main);
    const auto key = IndexKey(1);
    const auto path = m_path_root / "height-reopen";
    {
        FailingBlockIndexDB db{{.path = path, .cache_bytes = 1 << 20}};
        BOOST_REQUIRE(db.Write(key, uint32_t{5}, /*fSync=*/true));
        db.FlushDataToCache({{key, 6}});
        db.fail_call = 1;
        // Pruning consumes the only pending put. Its erase still needs retry.
        BOOST_CHECK_THROW(db.FlushCacheToDisk(MAX_BLOCK_INDEX + 10, 100000, /*fSync=*/false), dbwrapper_error);
        BOOST_REQUIRE(db.FlushCacheToDisk(MAX_BLOCK_INDEX + 10, 100000, /*fSync=*/false));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 2U);
        for (const bool sync : db.sync_calls) BOOST_CHECK(!sync);
        BOOST_REQUIRE(db.Write(key, uint32_t{20}, /*fSync=*/true));
        db.fail_call = 3;
        BOOST_CHECK_THROW(db.FlushErase({{key, 20}}), dbwrapper_error);
        BOOST_REQUIRE(db.FlushCacheToDisk(MAX_BLOCK_INDEX + 10, 100000, /*fSync=*/false));
        BOOST_CHECK_EQUAL(db.sync_calls.size(), 4U);
        BOOST_CHECK(db.sync_calls.back());
    }
    CBlockIndexDB reopened{{.path = path, .cache_bytes = 1 << 20}};
    uint32_t height{0};
    BOOST_CHECK(!reopened.ReadBlockHeight(key, height));
    BOOST_CHECK(!reopened.Exists(key));
}
// SYSCOIN END: Retrying inserts and deletions preserves data and batching.

// SYSCOIN: A replay-retention floor may move backward but never forward implicitly.
BOOST_AUTO_TEST_CASE(replay_prune_lock_never_raises_a_reorg_floor)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{m_node.exit_status};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{m_node.kernel->interrupt, blockman_opts};

    LOCK(::cs_main);
    const std::string name{"btcc-nevm-replay-test"};
    BOOST_CHECK_EQUAL(blockman.UpdatePruneLockLowerOnly(
                          name, node::PruneLockInfo{120}),
                      120);
    // SYSCOIN: Model DisconnectTip rewinding the live floor to a deep fork.
    // A later marker refresh at a higher carrier must preserve rollback data.
    blockman.UpdatePruneLock(name, node::PruneLockInfo{80});
    BOOST_CHECK_EQUAL(blockman.UpdatePruneLockLowerOnly(
                          name, node::PruneLockInfo{160}),
                      80);
    blockman.RemovePruneLock(name);
    BOOST_CHECK_EQUAL(blockman.UpdatePruneLockLowerOnly(
                          name, node::PruneLockInfo{160}),
                      160);
}

BOOST_AUTO_TEST_CASE(blockmanager_find_block_pos)
{
    const auto params {CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{m_node.exit_status};
    const BlockManager::Options blockman_opts{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{m_node.kernel->interrupt, blockman_opts};
    // simulate adding a genesis block normally
    BOOST_CHECK_EQUAL(blockman.SaveBlockToDisk(params->GenesisBlock(), 0, nullptr).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // simulate what happens during reindex
    // simulate a well-formed genesis block being found at offset 8 in the blk00000.dat file
    // the block is found at offset 8 because there is an 8 byte serialization header
    // consisting of 4 magic bytes + 4 length bytes before each block in a well-formed blk file.
    FlatFilePos pos{0, BLOCK_SERIALIZATION_HEADER_SIZE};
    BOOST_CHECK_EQUAL(blockman.SaveBlockToDisk(params->GenesisBlock(), 0, &pos).nPos, BLOCK_SERIALIZATION_HEADER_SIZE);
    // now simulate what happens after reindex for the first new block processed
    // the actual block contents don't matter, just that it's a block.
    // verify that the write position is at offset 0x12d.
    // this is a check to make sure that https://github.com/bitcoin/bitcoin/issues/21379 does not recur
    // 8 bytes (for serialization header) + 285 (for serialized genesis block) = 293
    // add another 8 bytes for the second block's serialization header and we get 293 + 8 = 301
    FlatFilePos actual{blockman.SaveBlockToDisk(params->GenesisBlock(), 1, nullptr)};
    BOOST_CHECK_EQUAL(actual.nPos, BLOCK_SERIALIZATION_HEADER_SIZE + ::GetSerializeSize(params->GenesisBlock(), CLIENT_VERSION) + BLOCK_SERIALIZATION_HEADER_SIZE);
}

BOOST_FIXTURE_TEST_CASE(blockmanager_scan_unlink_already_pruned_files, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    const auto& chainman = Assert(m_node.chainman);
    auto& blockman = chainman->m_blockman;
    const CBlockIndex* old_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    WITH_LOCK(chainman->GetMutex(), blockman.GetBlockFileInfo(old_tip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    // Prune the older block file, but don't unlink it
    int file_number;
    {
        LOCK(chainman->GetMutex());
        file_number = old_tip->GetBlockPos().nFile;
        blockman.PruneOneBlockFile(file_number);
    }

    const FlatFilePos pos(file_number, 0);

    // Check that the file is not unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // if m_have_pruned is not yet set
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!blockman.OpenBlockFile(pos, true).IsNull());

    // Check that the file is unlinked after ScanAndUnlinkAlreadyPrunedFiles
    // once m_have_pruned is set
    blockman.m_have_pruned = true;
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(blockman.OpenBlockFile(pos, true).IsNull());

    // Check that calling with already pruned files doesn't cause an error
    WITH_LOCK(chainman->GetMutex(), blockman.ScanAndUnlinkAlreadyPrunedFiles());

    // Check that the new tip file has not been removed
    const CBlockIndex* new_tip{WITH_LOCK(chainman->GetMutex(), return chainman->ActiveChain().Tip())};
    BOOST_CHECK_NE(old_tip, new_tip);
    const int new_file_number{WITH_LOCK(chainman->GetMutex(), return new_tip->GetBlockPos().nFile)};
    const FlatFilePos new_pos(new_file_number, 0);
    BOOST_CHECK(!blockman.OpenBlockFile(new_pos, true).IsNull());
}

BOOST_FIXTURE_TEST_CASE(blockmanager_block_data_availability, TestChain100Setup)
{
    // The goal of the function is to return the first not pruned block in the range [upper_block, lower_block].
    LOCK(::cs_main);
    auto& chainman = m_node.chainman;
    auto& blockman = chainman->m_blockman;
    const CBlockIndex& tip = *chainman->ActiveTip();

    // Function to prune all blocks from 'last_pruned_block' down to the genesis block
    const auto& func_prune_blocks = [&](CBlockIndex* last_pruned_block)
    {
        LOCK(::cs_main);
        CBlockIndex* it = last_pruned_block;
        while (it != nullptr && it->nStatus & BLOCK_HAVE_DATA) {
            it->nStatus &= ~BLOCK_HAVE_DATA;
            it = it->pprev;
        }
    };

    // 1) Return genesis block when all blocks are available
    BOOST_CHECK_EQUAL(blockman.GetFirstStoredBlock(tip), chainman->ActiveChain()[0]);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *chainman->ActiveChain()[0]));

    // 2) Check lower_block when all blocks are available
    CBlockIndex* lower_block = chainman->ActiveChain()[tip.nHeight / 2];
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *lower_block));

    // Prune half of the blocks
    int height_to_prune = tip.nHeight / 2;
    CBlockIndex* first_available_block = chainman->ActiveChain()[height_to_prune + 1];
    CBlockIndex* last_pruned_block = first_available_block->pprev;
    func_prune_blocks(last_pruned_block);

    // 3) The last block not pruned is in-between upper-block and the genesis block
    BOOST_CHECK_EQUAL(blockman.GetFirstStoredBlock(tip), first_available_block);
    BOOST_CHECK(blockman.CheckBlockDataAvailability(tip, *first_available_block));
    BOOST_CHECK(!blockman.CheckBlockDataAvailability(tip, *last_pruned_block));
}

BOOST_AUTO_TEST_CASE(blockmanager_flush_block_file)
{
    KernelNotifications notifications{m_node.exit_status};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{m_node.kernel->interrupt, blockman_opts};

    // Test blocks with no transactions, not even a coinbase
    CBlock block1;
    block1.nVersion = 1;
    CBlock block2;
    block2.nVersion = 2;
    CBlock block3;
    block3.nVersion = 3;

    // They are 80 bytes header + 1 byte 0x00 for vtx length
    constexpr int TEST_BLOCK_SIZE{81};

    // Blockstore is empty
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), 0);

    // Write the first block; dbp=nullptr means this block doesn't already have a disk
    // location, so allocate a free location and write it there.
    FlatFilePos pos1{blockman.SaveBlockToDisk(block1, /*nHeight=*/1, /*dbp=*/nullptr)};

    // Write second block
    FlatFilePos pos2{blockman.SaveBlockToDisk(block2, /*nHeight=*/2, /*dbp=*/nullptr)};

    // Two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // First two blocks are written as expected
    // Errors are expected because block data is junk, thrown AFTER successful read
    CBlock read_block;
    BOOST_CHECK_EQUAL(read_block.nVersion, 0);
    {
        ASSERT_DEBUG_LOG("ReadBlockFromDisk: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlockFromDisk(read_block, pos1));
        BOOST_CHECK_EQUAL(read_block.nVersion, 1);
    }
    {
        ASSERT_DEBUG_LOG("ReadBlockFromDisk: Errors in block header");
        BOOST_CHECK(!blockman.ReadBlockFromDisk(read_block, pos2));
        BOOST_CHECK_EQUAL(read_block.nVersion, 2);
    }

    // When FlatFilePos* dbp is given, SaveBlockToDisk() will not write or
    // overwrite anything to the flat file block storage. It will, however,
    // update the blockfile metadata. This is to facilitate reindexing
    // when the user has the blocks on disk but the metadata is being rebuilt.
    // Verify this behavior by attempting (and failing) to write block 3 data
    // to block 2 location.
    CBlockFileInfo* block_data = blockman.GetBlockFileInfo(0);
    BOOST_CHECK_EQUAL(block_data->nBlocks, 2);
    BOOST_CHECK(blockman.SaveBlockToDisk(block3, /*nHeight=*/3, /*dbp=*/&pos2) == pos2);
    // Metadata is updated...
    BOOST_CHECK_EQUAL(block_data->nBlocks, 3);
    // ...but there are still only two blocks in the file
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), (TEST_BLOCK_SIZE + BLOCK_SERIALIZATION_HEADER_SIZE) * 2);

    // Block 2 was not overwritten:
    //   SaveBlockToDisk() did not call WriteBlockToDisk() because `FlatFilePos* dbp` was non-null
    blockman.ReadBlockFromDisk(read_block, pos2);
    BOOST_CHECK_EQUAL(read_block.nVersion, 2);
}

// SYSCOIN: Durability barriers select the independent normal/assumed block
// streams by height and treat an uninitialized assumed stream as empty.
BOOST_AUTO_TEST_CASE(blockmanager_flush_chainstate_block_file_by_type)
{
    KernelNotifications notifications{m_node.exit_status};
    node::BlockManager::Options blockman_opts{
        .chainparams = Params(),
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{m_node.kernel->interrupt, blockman_opts};

    CBlock block;
    block.nVersion = 1;
    const FlatFilePos normal{
        blockman.SaveBlockToDisk(block, /*nHeight=*/1, /*dbp=*/nullptr)};
    blockman.m_snapshot_height = 2;

    BOOST_CHECK(blockman.FlushChainstateBlockFile(/*tip_height=*/1));
    BOOST_CHECK(blockman.FlushChainstateBlockFile(/*tip_height=*/2));

    block.nVersion = 2;
    const FlatFilePos assumed{
        blockman.SaveBlockToDisk(block, /*nHeight=*/2, /*dbp=*/nullptr)};
    BOOST_CHECK_NE(normal.nFile, assumed.nFile);
    BOOST_CHECK(blockman.FlushChainstateBlockFile(/*tip_height=*/2));
}

BOOST_AUTO_TEST_SUITE_END()
