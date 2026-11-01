// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <chain.h>
#include <compat/compat.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <streams.h>
#include <undo.h>
#include <util/chaintype.h>
#include <util/fs_helpers.h>
#include <validation.h>

#ifdef WIN32
#include <io.h>
#include <winioctl.h>
#endif

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

using node::BLOCK_SERIALIZATION_HEADER_SIZE;
using node::BlockManager;
using node::KernelNotifications;
using node::MAX_BLOCKFILE_SIZE;

namespace node {
struct BlockManagerTestAccess {
    static bool FindUndoPos(BlockManager& blockman, BlockValidationState& state, int file_number, FlatFilePos& pos, uint64_t add_size)
    {
        return blockman.FindUndoPos(state, file_number, pos, add_size);
    }

    static fs::path UndoFileName(const BlockManager& blockman, const FlatFilePos& pos)
    {
        return blockman.UndoFileSeq().FileName(pos);
    }
};
} // namespace node

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(blockmanager_undo_positions_do_not_wrap_at_4gb)
{
    const auto params{CreateChainParams(ArgsManager{}, ChainType::MAIN)};
    KernelNotifications notifications{m_node.exit_status};
    const BlockManager::Options options{
        .chainparams = *params,
        .blocks_dir = m_args.GetBlocksDirPath(),
        .notifications = notifications,
    };
    BlockManager blockman{m_node.kernel->interrupt, options};
    BOOST_REQUIRE(!blockman.SaveBlockToDisk(params->GenesisBlock(), 0, nullptr).IsNull());
    const uint64_t high{(uint64_t{1} << 32) + 100};
    blockman.GetBlockFileInfo(0)->nUndoSize = high;
    BlockValidationState state;
    FlatFilePos first;
    BOOST_REQUIRE(node::BlockManagerTestAccess::FindUndoPos(blockman, state, 0, first, 20));
    BOOST_CHECK_EQUAL(first.nPos, high);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0)->nUndoSize, high + 20);
    FlatFilePos second;
    BOOST_REQUIRE(node::BlockManagerTestAccess::FindUndoPos(blockman, state, 0, second, 30));
    BOOST_CHECK_EQUAL(second.nPos, high + 20);
    BOOST_CHECK_EQUAL(blockman.GetBlockFileInfo(0)->nUndoSize, high + 50);
    // Both positions stay in the same preallocation chunk; allocation creates no file.
    const auto undo_path{node::BlockManagerTestAccess::UndoFileName(blockman, first)};
    BOOST_CHECK(!fs::exists(undo_path));
#if !defined(WIN32)
    if (sizeof(off_t) < sizeof(int64_t)) return;
#endif
    const uint8_t marker{0x5a};
    {
        CAutoFile low{fsbridge::fopen(undo_path, "wb"), CLIENT_VERSION};
        BOOST_REQUIRE(!low.IsNull());
#ifdef WIN32
        DWORD returned{};
        BOOST_REQUIRE(DeviceIoControl(reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(low.Get()))),
                                      FSCTL_SET_SPARSE, nullptr, 0, nullptr, 0, &returned, nullptr));
#endif
        low << marker;
    }

    // Exercise the actual undo writer and checksum reader above the old 32-bit limit.
    const uint256 previous_hash{params->GenesisBlock().GetHash()};
    CBlockIndex previous;
    previous.phashBlock = &previous_hash;
    CBlockIndex block;
    block.pprev = &previous;
    block.nHeight = 1;
    {
        LOCK(::cs_main);
        block.nFile = 0;
        BOOST_REQUIRE(blockman.WriteUndoDataForBlock(CBlockUndo{}, state, block));
        BOOST_CHECK_EQUAL(block.nUndoPos, high + 50 + BLOCK_SERIALIZATION_HEADER_SIZE);
    }
    CBlockUndo decoded;
    BOOST_REQUIRE(blockman.UndoReadFromDisk(decoded, block));
    BOOST_CHECK(decoded.vtxundo.empty());
    CAutoFile low{fsbridge::fopen(undo_path, "rb"), CLIENT_VERSION};
    uint8_t actual{};
    low >> actual;
    BOOST_CHECK_EQUAL(actual, marker);
}

BOOST_AUTO_TEST_CASE(blockmanager_large_positions_serialize)
{
    const uint64_t high{(uint64_t{1} << 32) + 123};
    CBlockFileInfo file_info;
    file_info.nSize = high;
    file_info.nUndoSize = high + 1;
    DataStream file_stream;
    file_stream << file_info;
    CBlockFileInfo decoded_file_info;
    file_stream >> decoded_file_info;
    BOOST_CHECK_EQUAL(decoded_file_info.nSize, high);
    BOOST_CHECK_EQUAL(decoded_file_info.nUndoSize, high + 1);

    LOCK(::cs_main);
    CBlockIndex index;
    index.nStatus = BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
    index.nDataPos = high;
    index.nUndoPos = high + 1;
    DataStream index_stream;
    index_stream << CDiskBlockIndex{&index};
    CDiskBlockIndex decoded_index;
    index_stream >> decoded_index;
    BOOST_CHECK_EQUAL(decoded_index.nDataPos, high);
    BOOST_CHECK_EQUAL(decoded_index.nUndoPos, high + 1);
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

BOOST_AUTO_TEST_SUITE_END()
