// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <clientversion.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/context.h>
#include <node/kernel_notifications.h>
#include <script/solver.h>
#include <primitives/block.h>
#include <pow.h>
#include <streams.h>
#include <undo.h>
#include <util/chaintype.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>
#include <test/util/logging.h>
#include <test/util/setup_common.h>

#include <stdexcept>

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

// Storage-only fixture: the engine payload is opaque and never executed.
struct NEVMBlockStorageSetup : BasicTestingSetup {
    kernel::Notifications notifications;
    BlockManager blockman{
        m_node.kernel->interrupt,
        {.chainparams = Params(), .fast_prune = true,
         .blocks_dir = m_args.GetBlocksDirPath(), .notifications = notifications}};
    CBlock block;
    CBlockUndo undo;
    CBlockIndex* index{nullptr};
    const fs::path db_path{m_path_root / "replacement-index"};

    NEVMBlockStorageSetup() : BasicTestingSetup{ChainType::REGTEST} {}

    void Store(bool with_undo) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(
            DBParams{.path = db_path, .cache_bytes = 1 << 20});
        CBlockIndex* best_header{nullptr};
        const auto store = [&](const CBlock& value) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
            CBlockIndex* entry{blockman.AddToBlockIndex(value, best_header)};
            const auto pos{blockman.SaveBlockToDisk(value, entry->nHeight, nullptr)};
            BOOST_REQUIRE(!pos.IsNull());
            entry->nFile = pos.nFile;
            entry->nDataPos = pos.nPos;
            entry->nStatus |= BLOCK_HAVE_DATA;
            entry->RaiseValidity(BLOCK_VALID_SCRIPTS);
            entry->nTx = value.vtx.size();
            entry->nChainTx = entry->nTx + (entry->pprev ? entry->pprev->nChainTx : 0);
            return entry;
        };
        store(Params().GenesisBlock());
        block = Params().GenesisBlock();
        block.hashPrevBlock = block.GetHash();
        ++block.nTime;
        block.SetBaseVersion(1, Params().GetConsensus().nAuxpowChainId);
        block.SetNEVMVersion();
        block.vchNEVMBlockData = {0x31, 0x32, 0x33};
        // Match the complete merged-mining proof used by the regtest AuxPoW
        // fixtures, including the required parent coinbase header.
        block.SetAuxpowVersion(true);
        const uint256 child_hash{block.GetHash()};
        std::vector<uint8_t> merged{std::begin(pchMergedMiningHeader), std::end(pchMergedMiningHeader)};
        merged.insert(merged.end(), std::make_reverse_iterator(child_hash.end()),
                      std::make_reverse_iterator(child_hash.begin()));
        CDataStream suffix{SER_NETWORK, PROTOCOL_VERSION};
        suffix << uint32_t{1} << uint32_t{0};
        const auto suffix_bytes{MakeUCharSpan(suffix)};
        merged.insert(merged.end(), suffix_bytes.begin(), suffix_bytes.end());
        CMutableTransaction parent_coinbase;
        parent_coinbase.vin.resize(1);
        parent_coinbase.vin[0].prevout.SetNull();
        parent_coinbase.vin[0].scriptSig = CScript{} << merged;
        const auto coinbase{MakeTransactionRef(parent_coinbase)};
        CPureBlockHeader parent;
        parent.nVersion = 1;
        parent.hashMerkleRoot = coinbase->GetHash();
        while (!CheckProofOfWork(parent.GetHash(), block.nBits, Params().GetConsensus())) ++parent.nNonce;
        CDataStream proof{SER_NETWORK, PROTOCOL_VERSION};
        proof << coinbase << uint256{} << std::vector<uint256>{} << int32_t{0}
              << std::vector<uint256>{} << int32_t{0} << parent;
        auto auxpow{std::make_unique<CAuxPow>()};
        proof >> *auxpow;
        block.SetAuxpow(std::move(auxpow));
        BOOST_REQUIRE(HasValidProofOfWork({block}, Params().GetConsensus()));
        index = store(block);
        index->nSequenceId = 37;
        index->btcpPrevCommitment = IndexKey(21);
        index->pqBTCCReceiptCursorHeight = 8;
        index->pqBTCCReceiptStateHash = IndexKey(22);
        index->pqPaymentAuditReceiptStateHash = IndexKey(23);
        index->m_btcp_prev_contextually_validated = true;
        index->m_btcp_prev_contextual_commitment = IndexKey(24);
        if (with_undo) {
            undo.vtxundo.resize(1);
            undo.vtxundo[0].vprevout.emplace_back(
                CTxOut{123, CScript{} << OP_TRUE}, 7, false);
            BlockValidationState state;
            BOOST_REQUIRE(blockman.WriteUndoDataForBlock(undo, state, *index));
        }
        BOOST_REQUIRE(blockman.FlushChainstateBlockFile(index->nHeight));
        BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    }

    void CheckStored(const CBlockIndex& entry, Span<const uint8_t> payload)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        CBlock actual;
        BOOST_REQUIRE(blockman.ReadBlockFromDisk(actual, entry, /*load_auxiliary_data=*/false));
        CBlock expected{block};
        expected.vchNEVMBlockData.assign(payload.begin(), payload.end());
        CDataStream actual_bytes{SER_DISK, CLIENT_VERSION}, expected_bytes{SER_DISK, CLIENT_VERSION};
        actual_bytes << actual;
        expected_bytes << expected;
        BOOST_CHECK(actual_bytes.str() == expected_bytes.str());
        BOOST_CHECK(actual.GetHash() == block.GetHash());
        if (entry.nStatus & BLOCK_HAVE_UNDO) {
            CBlockUndo actual_undo;
            BOOST_REQUIRE(blockman.UndoReadFromDisk(actual_undo, entry));
            CDataStream actual_undo_bytes{SER_DISK, CLIENT_VERSION}, expected_undo_bytes{SER_DISK, CLIENT_VERSION};
            actual_undo_bytes << actual_undo;
            expected_undo_bytes << undo;
            BOOST_CHECK(actual_undo_bytes.str() == expected_undo_bytes.str());
        }
    }

    void RollBlockFile() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        blockman.GetBlockFileInfo(index->nFile)->nSize = 0x10000;
        const auto pos{blockman.SaveBlockToDisk(Params().GenesisBlock(), index->nHeight + 1, nullptr)};
        BOOST_REQUIRE(!pos.IsNull());
        BOOST_REQUIRE_NE(pos.nFile, index->nFile);
        BOOST_REQUIRE(blockman.FlushChainstateBlockFile(index->nHeight + 1));
    }
};

void CheckReplacementMetadata(const CBlockIndex& before, const CBlockIndex& after)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    CDiskBlockIndex expected{&before};
    expected.nFile = after.nFile;
    expected.nDataPos = after.nDataPos;
    expected.nUndoPos = after.nUndoPos;
    CDataStream expected_bytes{SER_DISK, CLIENT_VERSION}, actual_bytes{SER_DISK, CLIENT_VERSION};
    expected_bytes << CDiskBlockIndex{&expected};
    actual_bytes << CDiskBlockIndex{&after};
    BOOST_CHECK(expected_bytes.str() == actual_bytes.str());
    BOOST_CHECK_EQUAL(after.nChainTx, before.nChainTx);
    BOOST_CHECK_EQUAL(after.nSequenceId, before.nSequenceId);
    BOOST_CHECK(after.pprev == before.pprev);
    BOOST_CHECK(after.nChainWork == before.nChainWork);
    BOOST_CHECK_EQUAL(after.m_btcp_prev_contextually_validated,
                      before.m_btcp_prev_contextually_validated);
    BOOST_CHECK(after.m_btcp_prev_contextual_commitment == before.m_btcp_prev_contextual_commitment);
}

struct ReindexForStorageTest {
    const bool previous{node::fReindex.exchange(true)};
    ~ReindexForStorageTest() { node::fReindex = previous; }
};
} // namespace
// SYSCOIN END: Inject batch failures in the real transaction-height cache.

// use BasicTestingSetup here for the data directory configuration, setup, and cleanup
BOOST_FIXTURE_TEST_SUITE(blockmanager_tests, BasicTestingSetup)

BOOST_FIXTURE_TEST_CASE(nevm_payload_replacement_preserves_metadata_and_reopens, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/true);
    const CDiskBlockIndex before{index};
    const auto original_pos{index->GetBlockPos()};
    const auto original_undo_pos{index->GetUndoPos()};
    // Force the replacement into another small test block file.
    blockman.GetBlockFileInfo(index->nFile)->nSize = 0x10000;
    const std::vector<uint8_t> replacement{0x41, 0x42, 0x43, 0x44};
    BlockValidationState state;
    BOOST_REQUIRE(blockman.ReplaceNEVMBlockData(state, *index, replacement));
    BOOST_CHECK(state.IsValid());
    BOOST_CHECK_NE(index->nFile, original_pos.nFile);
    BOOST_CHECK(index->GetUndoPos() != original_undo_pos);
    CheckReplacementMetadata(before, *index);
    CheckStored(*index, replacement);
    CheckStored(before, block.vchNEVMBlockData);

    const auto repaired_hash{index->GetBlockHash()};
    CDataStream expected_bytes{SER_DISK, CLIENT_VERSION}, reopened_bytes{SER_DISK, CLIENT_VERSION};
    expected_bytes << CDiskBlockIndex{index};
    blockman.m_block_tree_db.reset();
    blockman.m_block_index.clear();
    blockman.m_prev_block_index.clear();
    blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(
        DBParams{.path = db_path, .cache_bytes = 1 << 20});
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    index = blockman.LookupBlockIndex(repaired_hash);
    BOOST_REQUIRE(index != nullptr);
    reopened_bytes << CDiskBlockIndex{index};
    BOOST_CHECK(expected_bytes.str() == reopened_bytes.str());
    CheckStored(*index, replacement);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_replacement_keeps_unrelated_dirty_indexes, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/false);
    const CDiskBlockIndex before{index};
    CBlockHeader unrelated_header{block.GetBlockHeader()};
    unrelated_header.hashPrevBlock = block.GetHash();
    ++unrelated_header.nNonce;
    CBlockIndex* best_header{index};
    CBlockIndex* unrelated{blockman.AddToBlockIndex(unrelated_header, best_header)};
    unrelated->btcpPrevCommitment = IndexKey(99);
    const std::vector<uint8_t> replacement{0x51, 0x52};
    BlockValidationState state;
    BOOST_REQUIRE(blockman.ReplaceNEVMBlockData(state, *index, replacement));
    BOOST_CHECK_EQUAL(index->nFile, before.nFile);
    BOOST_CHECK_NE(index->nDataPos, before.nDataPos);
    BOOST_CHECK(index->GetUndoPos().IsNull());
    CDiskBlockIndex stored_unrelated;
    BOOST_CHECK(!blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, unrelated->GetBlockHash()), stored_unrelated));
    CheckReplacementMetadata(before, *index);
    CheckStored(*index, replacement);
    BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    BOOST_REQUIRE(blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, unrelated->GetBlockHash()), stored_unrelated));
    BOOST_CHECK(stored_unrelated.btcpPrevCommitment == IndexKey(99));
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_replacement_failed_flush_keeps_old_positions, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/false);
    const CDiskBlockIndex before{index};
    blockman.GetBlockFileInfo(index->nFile)->nSize = 0x10000;
    // The replacement block can be appended, but its destination undo-file
    // durability barrier cannot open a directory as a regular file.
    const fs::path blocked_undo{m_args.GetBlocksDirPath() / "rev00001.dat"};
    BOOST_REQUIRE(fs::create_directory(blocked_undo));
    const std::vector<uint8_t> replacement{0x61, 0x62};
    BlockValidationState state;
    BOOST_CHECK(!blockman.ReplaceNEVMBlockData(state, *index, replacement));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(index->GetBlockPos() == before.GetBlockPos());
    BOOST_CHECK(index->GetUndoPos() == before.GetUndoPos());
    CheckReplacementMetadata(before, *index);
    CheckStored(*index, block.vchNEVMBlockData);
    CDiskBlockIndex persisted;
    BOOST_REQUIRE(blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, index->GetBlockHash()), persisted));
    BOOST_CHECK_EQUAL(persisted.nFile, before.nFile);
    BOOST_CHECK_EQUAL(persisted.nDataPos, before.nDataPos);
    BOOST_REQUIRE(fs::remove(blocked_undo));
    state = BlockValidationState{};
    BOOST_REQUIRE(blockman.ReplaceNEVMBlockData(state, *index, replacement));
    CheckStored(*index, replacement);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_replacement_requires_persisted_index, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/false);
    const auto old_pos{index->GetBlockPos()};
    BOOST_REQUIRE(blockman.m_block_tree_db->Erase(
        std::make_pair(uint8_t{'b'}, index->GetBlockHash()), /*fSync=*/true));
    const std::vector<uint8_t> replacement{0x71, 0x72};
    BlockValidationState state;
    BOOST_CHECK(!blockman.ReplaceNEVMBlockData(state, *index, replacement));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-replacement-index-not-persisted");
    BOOST_CHECK(index->GetBlockPos() == old_pos);
    CheckStored(*index, block.vchNEVMBlockData);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_reindex_adopts_existing_record, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/false);
    const CDiskBlockIndex before{index};
    CBlock candidate{block};
    candidate.vchNEVMBlockData = {0x81, 0x82};
    const auto candidate_pos{blockman.SaveBlockToDisk(candidate, index->nHeight, nullptr)};
    BOOST_REQUIRE(!candidate_pos.IsNull());
    BOOST_REQUIRE(blockman.FlushChainstateBlockFile(index->nHeight));
    const auto usage_before{blockman.CalculateCurrentUsage()};
    ReindexForStorageTest reindex;
    BlockValidationState state;
    BOOST_REQUIRE(blockman.AdoptNEVMBlockDataForReindex(state, *index, candidate, candidate_pos));
    BOOST_CHECK(index->GetBlockPos() == candidate_pos);
    BOOST_CHECK_EQUAL(blockman.CalculateCurrentUsage(), usage_before);
    CheckReplacementMetadata(before, *index);
    CheckStored(*index, candidate.vchNEVMBlockData);
    CDiskBlockIndex persisted;
    BOOST_REQUIRE(blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, index->GetBlockHash()), persisted));
    BOOST_CHECK_EQUAL(persisted.nDataPos, before.nDataPos);
    BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    BOOST_REQUIRE(blockman.m_block_tree_db->Read(
        std::make_pair(uint8_t{'b'}, index->GetBlockHash()), persisted));
    BOOST_CHECK_EQUAL(persisted.nDataPos, candidate_pos.nPos);
}

BOOST_FIXTURE_TEST_CASE(nevm_payload_reindex_rejects_core_changes_and_wrong_context, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/false);
    const auto original_pos{index->GetBlockPos()};
    CBlock candidate{block};
    candidate.vchNEVMBlockData = {0x91, 0x92};
    const auto candidate_pos{blockman.SaveBlockToDisk(candidate, index->nHeight, nullptr)};
    BOOST_REQUIRE(!candidate_pos.IsNull());
    BlockValidationState state;
    BOOST_CHECK(!blockman.AdoptNEVMBlockDataForReindex(state, *index, candidate, candidate_pos));
    ReindexForStorageTest reindex;
    CBlock changed_body{candidate};
    changed_body.vtx.clear();
    state = BlockValidationState{};
    BOOST_CHECK(!blockman.AdoptNEVMBlockDataForReindex(state, *index, changed_body, candidate_pos));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-reindex-core-block-mismatch");
    CBlock changed_wrapper{candidate};
    CPureBlockHeader alternate_parent;
    alternate_parent.nVersion = 1;
    alternate_parent.nTime = 1;
    const auto parent_coinbase{candidate.auxpow->getCoinbaseTx()};
    alternate_parent.hashMerkleRoot = parent_coinbase->GetHash();
    while (!CheckProofOfWork(alternate_parent.GetHash(), block.nBits, Params().GetConsensus())) ++alternate_parent.nNonce;
    CDataStream alternate_proof{SER_NETWORK, PROTOCOL_VERSION};
    alternate_proof << parent_coinbase << uint256{} << std::vector<uint256>{} << int32_t{0}
                    << std::vector<uint256>{} << int32_t{0} << alternate_parent;
    auto alternate_auxpow{std::make_unique<CAuxPow>()};
    alternate_proof >> *alternate_auxpow;
    changed_wrapper.SetAuxpow(std::move(alternate_auxpow));
    BOOST_CHECK(changed_wrapper.GetHash() == candidate.GetHash());
    BOOST_REQUIRE(HasValidProofOfWork({changed_wrapper}, Params().GetConsensus()));
    state = BlockValidationState{};
    BOOST_CHECK(!blockman.AdoptNEVMBlockDataForReindex(state, *index, changed_wrapper, candidate_pos));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-reindex-core-block-mismatch");
    CBlockUndo empty_undo;
    state = BlockValidationState{};
    BOOST_REQUIRE(blockman.WriteUndoDataForBlock(empty_undo, state, *index));
    state = BlockValidationState{};
    BOOST_CHECK(!blockman.AdoptNEVMBlockDataForReindex(state, *index, candidate, candidate_pos));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "nevm-payload-reindex-adoption-unavailable");
    BOOST_CHECK(index->GetBlockPos() == original_pos);
}

BOOST_FIXTURE_TEST_CASE(nevm_pruned_coinbase_proof_survives_unlink_and_reopen, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/true);
    RollBlockFile();
    const auto carrier{index->GetBlockHash()};
    const auto old_pos{index->GetBlockPos()};
    const auto block_path{blockman.GetBlockPosFilename(old_pos)};
    const auto undo_path{m_args.GetBlocksDirPath() / "rev00000.dat"};
    const auto coinbase_hash{block.vtx.front()->GetHash()};
    blockman.PruneOneBlockFile(old_pos.nFile);
    blockman.m_have_pruned = true;
    BOOST_REQUIRE(blockman.m_block_tree_db->WriteFlag("prunedblockfiles", true));
    BOOST_REQUIRE(blockman.WriteBlockIndexDB());
    BOOST_REQUIRE(blockman.CheckNEVMPrunedBlockProofs());
    BOOST_REQUIRE(blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!fs::exists(block_path));
    BOOST_CHECK(!fs::exists(undo_path));
    // Discard the full body, including AuxPoW and opaque engine payload.
    block.SetNull();
    blockman.m_block_tree_db.reset();
    blockman.m_block_index.clear();
    blockman.m_prev_block_index.clear();
    blockman.m_block_tree_db = std::make_unique<node::BlockTreeDB>(
        DBParams{.path = db_path, .cache_bytes = 1 << 20});
    BOOST_REQUIRE(blockman.LoadBlockIndexDB(std::nullopt));
    index = blockman.LookupBlockIndex(carrier);
    BOOST_REQUIRE(index != nullptr);
    BOOST_CHECK(!(index->nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO)));
    BOOST_REQUIRE(blockman.CheckNEVMPrunedBlockProofs());
    node::NEVMPrunedRootProof proof;
    BOOST_REQUIRE(blockman.m_block_tree_db->ReadNEVMPrunedRootProof(carrier, proof));
    BOOST_CHECK_EQUAL(proof.version, node::NEVMPrunedRootProof::VERSION);
    BOOST_REQUIRE(proof.coinbase != nullptr);
    BOOST_CHECK(proof.coinbase->GetHash() == coinbase_hash);
    BOOST_CHECK_EQUAL(proof.merkle_tree.GetNumTransactions(), index->nTx);
    std::vector<uint256> matches;
    std::vector<unsigned int> positions;
    BOOST_CHECK(proof.merkle_tree.ExtractMatches(matches, positions) == index->hashMerkleRoot);
    BOOST_REQUIRE_EQUAL(matches.size(), 1U);
    BOOST_REQUIRE_EQUAL(positions.size(), 1U);
    BOOST_CHECK(matches.front() == coinbase_hash);
    BOOST_CHECK_EQUAL(positions.front(), 0U);
    CBlock unavailable;
    BOOST_CHECK(!blockman.ReadBlockFromDisk(unavailable, *index, /*load_auxiliary_data=*/false));
    // An inactive NEVM-version side branch need not contain valid NEVM fields.
    // Its inclusion proof is still required; it cannot supply recovery roots.
    CNEVMHeader header;
    BOOST_CHECK(!blockman.ReadNEVMPrunedHeader(header, *index));
}

BOOST_FIXTURE_TEST_CASE(nevm_pruned_proof_corruption_blocks_startup_cleanup, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/true);
    RollBlockFile();
    const auto old_pos{index->GetBlockPos()};
    const auto block_path{blockman.GetBlockPosFilename(old_pos)};
    const auto undo_path{m_args.GetBlocksDirPath() / "rev00000.dat"};
    const auto carrier{index->GetBlockHash()};
    const auto proof_key{std::make_pair(uint8_t{'N'}, carrier)};
    blockman.PruneOneBlockFile(old_pos.nFile);
    blockman.m_have_pruned = true;
    node::NEVMPrunedRootProof original;
    BOOST_REQUIRE(blockman.m_block_tree_db->ReadNEVMPrunedRootProof(carrier, original));
    const auto reject_cleanup = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        BOOST_CHECK(!blockman.CheckNEVMPrunedBlockProofs());
        BOOST_CHECK(!blockman.ScanAndUnlinkAlreadyPrunedFiles());
        BOOST_CHECK(fs::exists(block_path));
        BOOST_CHECK(fs::exists(undo_path));
    };
    const auto restore = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        BOOST_REQUIRE(blockman.m_block_tree_db->WriteNEVMPrunedRootProofs({{carrier, original}}));
    };

    BOOST_REQUIRE(blockman.m_block_tree_db->Erase(proof_key, /*fSync=*/true));
    reject_cleanup();
    // A snapshot can give an undownloaded header a synthetic nTx. It has no
    // pruned body to authenticate. An actually received, subsequently failed
    // branch must still retain its proof for a possible reconsideration.
    const auto stored_status{index->nStatus};
    index->nStatus = BLOCK_VALID_TREE | BLOCK_ASSUMED_VALID;
    BOOST_CHECK(blockman.CheckNEVMPrunedBlockProofs());
    index->nStatus = stored_status | BLOCK_FAILED_VALID;
    reject_cleanup();
    index->nStatus = stored_status;
    // A truncated record must fail through the real database deserializer.
    BOOST_REQUIRE(blockman.m_block_tree_db->Write(proof_key, uint8_t{1}, /*fSync=*/true));
    reject_cleanup();
    BOOST_REQUIRE(blockman.m_block_tree_db->Write(
        proof_key, std::make_pair(original, uint8_t{0}), /*fSync=*/true));
    reject_cleanup();
    for (const bool unsupported_version : {false, true}) {
        auto invalid{original};
        if (unsupported_version) {
            ++invalid.version;
        } else {
            invalid.merkle_tree = CPartialMerkleTree{};
        }
        BOOST_REQUIRE(blockman.m_block_tree_db->Write(proof_key, invalid, /*fSync=*/true));
        reject_cleanup();
    }
    auto wrong_coinbase{original};
    CMutableTransaction altered{*original.coinbase};
    ++altered.nLockTime;
    wrong_coinbase.coinbase = MakeTransactionRef(altered);
    BOOST_REQUIRE(blockman.m_block_tree_db->WriteNEVMPrunedRootProofs({{carrier, wrong_coinbase}}));
    reject_cleanup();
    restore();
    ++index->nTx;
    reject_cleanup();
    --index->nTx;
    const auto merkle_root{index->hashMerkleRoot};
    index->hashMerkleRoot = IndexKey(55);
    reject_cleanup();
    index->hashMerkleRoot = merkle_root;
    BOOST_REQUIRE(blockman.CheckNEVMPrunedBlockProofs());
    BOOST_REQUIRE(blockman.ScanAndUnlinkAlreadyPrunedFiles());
    BOOST_CHECK(!fs::exists(block_path));
    BOOST_CHECK(!fs::exists(undo_path));
}

BOOST_FIXTURE_TEST_CASE(nevm_pruning_unreadable_or_corrupt_body_preserves_metadata, NEVMBlockStorageSetup)
{
    LOCK(cs_main);
    Store(/*with_undo=*/true);
    const auto old_pos{index->GetBlockPos()};
    const auto block_path{blockman.GetBlockPosFilename(old_pos)};
    const auto undo_path{m_args.GetBlocksDirPath() / "rev00000.dat"};
    const auto metadata = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        CDataStream bytes{SER_DISK, CLIENT_VERSION};
        bytes << *blockman.GetBlockFileInfo(old_pos.nFile);
        for (const auto& [hash, entry] : blockman.m_block_index) bytes << CDiskBlockIndex{&entry};
        return bytes.str();
    };
    const auto before{metadata()};
    for (const bool unreadable : {false, true}) {
        if (unreadable) {
            fs::resize_file(block_path, old_pos.nPos + 1);
        } else {
            CBlock corrupt{block};
            CMutableTransaction altered{*corrupt.vtx.front()};
            ++altered.nLockTime;
            corrupt.vtx.front() = MakeTransactionRef(altered);
            auto file{blockman.OpenBlockFile(old_pos)};
            BOOST_REQUIRE(!file.IsNull());
            file << corrupt;
        }
        const auto size_before{fs::file_size(block_path)};
        BOOST_CHECK_THROW(blockman.PruneOneBlockFile(old_pos.nFile), std::runtime_error);
        BOOST_CHECK(metadata() == before);
        BOOST_CHECK_EQUAL(fs::file_size(block_path), size_before);
        BOOST_CHECK(fs::exists(undo_path));
        node::NEVMPrunedRootProof proof;
        BOOST_CHECK(!blockman.m_block_tree_db->ReadNEVMPrunedRootProof(index->GetBlockHash(), proof));
        auto file{blockman.OpenBlockFile(old_pos)};
        BOOST_REQUIRE(!file.IsNull());
        file << block;
    }
    CheckStored(*index, block.vchNEVMBlockData);
}

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
