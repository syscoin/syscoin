// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_migration.h>

#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <dbwrapper.h>
#include <evo/deterministicmns.h>
#include <flatfile.h>
#include <hash.h>
#include <nevm/rlp.h>
#include <nevm/sha3.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/pq_legacy_upgrade.h>
#include <pow.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <fstream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {
struct LegacyMigrationSetup : ChainTestingSetup {
    Consensus::Params& consensus;
    const Consensus::Params original_consensus;
    const bool original_reindex_geth;
    std::vector<uint256> hashes;
    std::vector<CBlock> blocks;
    std::vector<unsigned int> positions;
    std::vector<unsigned int> sizes;

    LegacyMigrationSetup()
        : ChainTestingSetup{ChainType::REGTEST},
          consensus{const_cast<Consensus::Params&>(m_node.chainman->GetConsensus())},
          original_consensus{consensus},
          original_reindex_geth{fReindexGeth.load()}
    {
        m_node.chainman->m_blockman.m_block_tree_db.reset();
        consensus.DIP0003Height = 1;
        consensus.nPQActivationHeight = 3;
        consensus.nNEVMStartBlock = 2;
        fReindexGeth = false;
    }

    ~LegacyMigrationSetup()
    {
        consensus = original_consensus;
        fReindexGeth = original_reindex_geth;
    }

    fs::path Path(const char* name) const
    {
        return m_node.chainman->m_options.datadir / name;
    }

    DBParams DB(const char* name) const
    {
        return {.path = Path(name), .cache_bytes = 1 << 20};
    }

    fs::path BlockFile() const
    {
        return m_node.chainman->m_blockman.GetBlockPosFilename({0, 0});
    }

    void AttachNEVMPayload(CBlock& block, CMutableTransaction& coinbase, int32_t height)
    {
        block.SetNEVMVersion();
        CNEVMHeader parent;
        if (blocks.back().IsNEVM()) {
            BlockValidationState state;
            BOOST_REQUIRE(GetNEVMData(state, blocks.back(), parent));
        }
        const uint64_t number{static_cast<uint64_t>(height - consensus.nNEVMStartBlock + 1)};
        // An ordinary nine-field legacy transaction. This fixture checks body
        // integrity, not execution or the transaction's signing authority.
        dev::RLPStream transaction(9);
        transaction.append(0U);
        transaction.append(1U);
        transaction.append(50000U);
        transaction.append(dev::bytes(20, 1));
        transaction.append(0U);
        transaction.append(dev::bytes{0x11});
        transaction.append(27U);
        transaction.append(1U);
        transaction.append(1U);
        // Index zero is RLP 0x80. Its single-leaf hex-prefix path is 0x2080;
        // constructing that leaf directly avoids duplicating a trie builder.
        dev::RLPStream leaf(2);
        leaf.append(dev::bytes{0x20, 0x80});
        leaf.append(dev::bytes{transaction.out()});
        const auto tx_root{dev::sha3(leaf.out()).asBytes()};
        const auto empty_root{dev::sha3(dev::bytes{0x80}).asBytes()};
        dev::RLPStream header(15);
        header.append(dev::bytes(parent.nBlockHash.begin(), parent.nBlockHash.end()));
        header.append(dev::EmptyListSHA3.asBytes());
        header.append(dev::bytes(20, 0));
        header.append(empty_root);
        header.append(tx_root);
        header.append(empty_root);
        header.append(dev::bytes(256, 0));
        header.append(1U);
        header.append(number);
        header.append(30000000U);
        header.append(25000U);
        header.append(number);
        header.append(dev::bytes{});
        header.append(dev::bytes(32, 0));
        header.append(dev::bytes(8, 0));
        CNEVMHeader commitment;
        const auto digest{dev::sha3(header.out()).asBytes()};
        std::copy(digest.begin(), digest.end(), commitment.nBlockHash.begin());
        std::copy(tx_root.begin(), tx_root.end(), commitment.nTxRoot.begin());
        std::copy(empty_root.begin(), empty_root.end(), commitment.nReceiptRoot.begin());
        CDataStream serialized{SER_NETWORK, PROTOCOL_VERSION};
        serialized << commitment;
        std::vector<unsigned char> payload(std::begin(NEVM_MAGIC_BYTES), std::end(NEVM_MAGIC_BYTES));
        const auto commitment_bytes{MakeUCharSpan(serialized)};
        payload.insert(payload.end(), commitment_bytes.begin(), commitment_bytes.end());
        coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
        dev::RLPStream body(3);
        body.appendRaw(header.out());
        body.appendList(1);
        body.appendRaw(transaction.out());
        body.appendList(0);
        block.vchNEVMBlockData = dev::bytes{body.out()};
    }

    void MakeLegacy(int32_t height = 5, bool with_witness = false, bool with_nevm = false)
    {
        LOCK(cs_main);
        if (with_witness) consensus.SegwitHeight = 1;
        // The bodies, framing, hashes and proof of work are real. The database
        // metadata below remains a synthetic legacy-provenance fixture, not an
        // old-binary migration or a contextual replay of these blocks.
        blocks.push_back(m_node.chainman->GetParams().GenesisBlock());
        for (int32_t h{1}; h <= height; ++h) {
            CBlock block;
            block.SetBaseVersion(4, consensus.nAuxpowChainId);
            block.hashPrevBlock = blocks.back().GetHash();
            block.nTime = blocks.back().nTime + 1;
            block.nBits = blocks.front().nBits;
            CMutableTransaction coinbase;
            coinbase.vin.resize(1);
            coinbase.vin[0].prevout.SetNull();
            coinbase.vin[0].scriptSig = CScript{} << h << OP_0;
            coinbase.vout.emplace_back(1, CScript{} << OP_TRUE);
            if (with_witness) {
                const std::vector<unsigned char> nonce(32, 0);
                coinbase.vin.front().scriptWitness.stack.push_back(nonce);
                // A coinbase-only block has the all-zero witness merkle root.
                uint256 commitment;
                CHash256().Write(commitment).Write(nonce).Finalize(commitment);
                std::vector<unsigned char> commitment_bytes{0xaa, 0x21, 0xa9, 0xed};
                commitment_bytes.insert(commitment_bytes.end(), commitment.begin(), commitment.end());
                coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << commitment_bytes);
            }
            if (with_nevm && h >= consensus.nNEVMStartBlock) {
                AttachNEVMPayload(block, coinbase, h);
            }
            block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
            block.hashMerkleRoot = BlockMerkleRoot(block);
            while (!CheckProofOfWork(block.GetHash(), block.nBits, consensus)) ++block.nNonce;
            BlockValidationState state;
            BOOST_REQUIRE_MESSAGE(CheckBlock(block, state, consensus), state.ToString());
            blocks.push_back(std::move(block));
        }
        fs::create_directories(BlockFile().parent_path());
        {
            std::ofstream file{BlockFile(), std::ios::binary};
            for (const auto& block : blocks) {
                CDataStream body{SER_DISK, CLIENT_VERSION};
                body << block;
                CDataStream framing{SER_DISK, CLIENT_VERSION};
                framing << m_node.chainman->GetParams().MessageStart() << uint32_t{static_cast<uint32_t>(body.size())};
                file.write(reinterpret_cast<const char*>(framing.data()), framing.size());
                BOOST_REQUIRE(file.good());
                positions.push_back(static_cast<unsigned int>(file.tellp()));
                sizes.push_back(body.size());
                file.write(reinterpret_cast<const char*>(body.data()), body.size());
                BOOST_REQUIRE(file.good());
                hashes.push_back(block.GetHash());
            }
        }
        {
            node::BlockTreeDB db{DB("blocks/index")};
            for (int32_t h{0}; h <= height; ++h) {
                CDiskBlockIndex index;
                index.nHeight = h;
                index.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
                index.nFile = 0;
                index.nDataPos = positions[h];
                index.nTx = blocks[h].vtx.size();
                index.hashPrev = h == 0 ? uint256{} : hashes[h - 1];
                index.nVersion = blocks[h].nVersion;
                index.hashMerkleRoot = blocks[h].hashMerkleRoot;
                index.nTime = blocks[h].nTime;
                index.nBits = blocks[h].nBits;
                index.nNonce = blocks[h].nNonce;
                BOOST_REQUIRE(db.Write(std::pair{uint8_t{'b'}, hashes[h]}, index, true));
            }
        }
        {
            CDBWrapper coins{DB("chainstate")};
            BOOST_REQUIRE(coins.Write(uint8_t{'B'}, hashes.back(), true));
        }
        {
            CDBWrapper dmn{DB("evodb_dmn")};
            BOOST_REQUIRE(dmn.Write(hashes.back(),
                CDeterministicMNList{hashes.back(), height, 0}, true));
        }
        if (height >= consensus.nNEVMStartBlock) {
            CDBWrapper roots{DB("nevmtxroots")};
            BOOST_REQUIRE(roots.Write(uint256{100},
                std::pair{uint256{101}, uint256{102}}, true));
        }
    }

    bool Plan(node::ChainstateLoadOptions& options, bilingual_str& error)
    {
        LOCK(cs_main);
        return node::PreparePQLegacyUpgrade(*m_node.chainman, options,
                                           m_cache_sizes, error);
    }

    void CheckUncapturedAndUnchanged()
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_CHECK(!journal.ReadUpgrade());
        BOOST_CHECK(!journal.HasBLSFreeHistory());
        CDBWrapper coins{DB("chainstate")};
        uint256 best;
        BOOST_REQUIRE(coins.Read(uint8_t{'B'}, best));
        BOOST_CHECK(best == hashes.back());
    }

    void CheckRejectedWithoutReset()
    {
        node::ChainstateLoadOptions options;
        bilingual_str error;
        BOOST_CHECK(!Plan(options, error));
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(!options.reindex);
        BOOST_CHECK(!options.reindex_chainstate);
        BOOST_CHECK(!options.fReindexGeth);
        BOOST_CHECK(!fReindexGeth);
        CheckUncapturedAndUnchanged();
    }

    void ReplaceBody(std::size_t height, const CBlock& block)
    {
        CDataStream body{SER_DISK, CLIENT_VERSION};
        body << block;
        BOOST_REQUIRE_EQUAL(body.size(), sizes[height]);
        std::fstream file{BlockFile(), std::ios::binary | std::ios::in | std::ios::out};
        file.seekp(positions[height]);
        file.write(reinterpret_cast<const char*>(body.data()), body.size());
        BOOST_REQUIRE(file.good());
    }

    void ReplaceNEVMPayloadOnly(std::size_t height, CBlock& corrupt)
    {
        const auto& original{blocks[height]};
        BOOST_REQUIRE(original.IsNEVM());
        BOOST_CHECK(corrupt.GetHash() == hashes[height]);
        BOOST_CHECK(corrupt.vtx == original.vtx);
        BOOST_CHECK(BlockMerkleRoot(corrupt) == original.hashMerkleRoot);
        BOOST_CHECK(BlockWitnessMerkleRoot(corrupt) == BlockWitnessMerkleRoot(original));
        BOOST_CHECK(corrupt.vchNEVMBlockData != original.vchNEVMBlockData);
        BOOST_REQUIRE_EQUAL(corrupt.vchNEVMBlockData.size(), original.vchNEVMBlockData.size());
        // Do not accidentally exercise CheckBlock's cached success shortcut.
        corrupt.fChecked = false;
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(CheckBlock(corrupt, state, consensus), state.ToString());
        CNEVMHeader expected, supplied;
        BOOST_REQUIRE(GetNEVMData(state, original, expected));
        BOOST_REQUIRE(GetNEVMData(state, corrupt, supplied));
        BOOST_CHECK(expected.nBlockHash == supplied.nBlockHash);
        BOOST_CHECK(expected.nTxRoot == supplied.nTxRoot);
        BOOST_CHECK(expected.nReceiptRoot == supplied.nReceiptRoot);
        ReplaceBody(height, corrupt);
    }

    void ReplaceRecordSize(std::size_t height, uint32_t size)
    {
        CDataStream bytes{SER_DISK, CLIENT_VERSION};
        bytes << size;
        std::fstream file{BlockFile(), std::ios::binary | std::ios::in | std::ios::out};
        file.seekp(positions[height] - sizeof(uint32_t));
        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        BOOST_REQUIRE(file.good());
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_legacy_migration_tests, LegacyMigrationSetup)

BOOST_AUTO_TEST_CASE(header_only_retained_tip_fails_before_capture)
{
    MakeLegacy();
    // The previous preflight accepted this exact extent: the indexed header
    // exists, but not even the transaction count needed for replay survives.
    fs::resize_file(BlockFile(), positions.back() + 80);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(parseable_transaction_corruption_fails_before_capture)
{
    MakeLegacy();
    CBlock corrupt{blocks[2]};
    CMutableTransaction coinbase{*corrupt.vtx.front()};
    ++coinbase.vout.front().nValue;
    corrupt.vtx.front() = MakeTransactionRef(std::move(coinbase));
    BOOST_CHECK(corrupt.GetHash() == hashes[2]);
    BOOST_CHECK(BlockMerkleRoot(corrupt) != corrupt.hashMerkleRoot);
    ReplaceBody(2, corrupt);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(intact_witness_history_can_be_captured)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/true);
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.reindex_chainstate);
    BOOST_CHECK(options.fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(journal.ReadUpgrade()->legacy_tip_hash == hashes.back());
}

BOOST_AUTO_TEST_CASE(witness_only_corruption_fails_before_capture)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/true);
    CBlock corrupt{blocks[2]};
    CMutableTransaction coinbase{*corrupt.vtx.front()};
    coinbase.vin.front().scriptWitness.stack.front()[0] = 1;
    corrupt.vtx.front() = MakeTransactionRef(std::move(coinbase));
    BOOST_CHECK(corrupt.GetHash() == hashes[2]);
    BOOST_CHECK(BlockMerkleRoot(corrupt) == corrupt.hashMerkleRoot);
    BOOST_CHECK(corrupt.vtx.front()->GetWitnessHash() != blocks[2].vtx.front()->GetWitnessHash());
    ReplaceBody(2, corrupt);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(intact_nevm_payload_history_can_be_captured)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/false, /*with_nevm=*/true);
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.reindex_chainstate);
    BOOST_CHECK(options.fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(journal.ReadUpgrade()->legacy_tip_hash == hashes.back());
}

BOOST_AUTO_TEST_CASE(malformed_nevm_rlp_fails_before_capture)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/false, /*with_nevm=*/true);
    CBlock corrupt{blocks[2]};
    // Claim an impossible eight-byte RLP list length without changing the
    // Core record extent, transaction commitments or proof of work.
    corrupt.vchNEVMBlockData.front() = 0xff;
    BOOST_CHECK_THROW(dev::RLP{corrupt.vchNEVMBlockData}, std::exception);
    ReplaceNEVMPayloadOnly(2, corrupt);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(nevm_header_hash_corruption_fails_before_capture)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/false, /*with_nevm=*/true);
    CBlock corrupt{blocks[2]};
    const dev::RLP encoded{corrupt.vchNEVMBlockData};
    const auto offset{encoded[0][0].toBytesConstRef().data() - corrupt.vchNEVMBlockData.data()};
    corrupt.vchNEVMBlockData[offset] ^= 1;
    // It remains parseable Ethereum RLP; only its binding to the coinbase's
    // committed NEVM header hash is broken.
    BOOST_CHECK_EQUAL(dev::RLP{corrupt.vchNEVMBlockData}[0].itemCount(), 15U);
    ReplaceNEVMPayloadOnly(2, corrupt);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(nevm_transaction_body_corruption_fails_before_capture)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/false, /*with_nevm=*/true);
    CBlock corrupt{blocks[2]};
    const dev::RLP encoded{corrupt.vchNEVMBlockData};
    const auto offset{encoded[1][0][5].toBytesConstRef().data() - corrupt.vchNEVMBlockData.data()};
    corrupt.vchNEVMBlockData[offset] ^= 1;
    // The authenticated Ethereum header itself is unchanged. Detecting this
    // corruption therefore requires checking the transaction trie root.
    BOOST_CHECK(dev::RLP{corrupt.vchNEVMBlockData}[0].data().toBytes() ==
                dev::RLP{blocks[2].vchNEVMBlockData}[0].data().toBytes());
    ReplaceNEVMPayloadOnly(2, corrupt);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(noncanonical_transaction_count_fails_before_capture)
{
    MakeLegacy();
    const auto original_size{fs::file_size(BlockFile())};
    {
        std::fstream file{BlockFile(), std::ios::binary | std::ios::in | std::ios::out};
        file.seekp(positions[2] + 80);
        // CompactSize(1) encoded with the noncanonical three-byte form. The
        // block extent and its framing still exist in full.
        const unsigned char count[]{0xfd, 0x01, 0x00};
        file.write(reinterpret_cast<const char*>(count), sizeof(count));
        BOOST_REQUIRE(file.good());
    }
    BOOST_CHECK_EQUAL(fs::file_size(BlockFile()), original_size);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(wrong_indexed_block_body_fails_before_capture)
{
    MakeLegacy();
    // An independently valid block of the same size at the requested position
    // must not establish provenance for the indexed hash.
    ReplaceBody(2, blocks[3]);
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(malformed_record_framing_fails_before_capture)
{
    MakeLegacy();
    const auto height{std::size_t{2}};
    for (const uint32_t size : {uint32_t{0}, uint32_t{79}, sizes[height] - 1,
                                sizes[height] + 1, std::numeric_limits<uint32_t>::max()}) {
        BOOST_TEST_CONTEXT("declared block size " << size) {
            ReplaceRecordSize(height, size);
            CheckRejectedWithoutReset();
        }
    }
    ReplaceRecordSize(height, sizes[height]);
    {
        std::fstream file{BlockFile(), std::ios::binary | std::ios::in | std::ios::out};
        file.seekp(positions[height] - 8);
        const std::string wrong_magic(4, '\0');
        file.write(wrong_magic.data(), wrong_magic.size());
        BOOST_REQUIRE(file.good());
    }
    CheckRejectedWithoutReset();
}

BOOST_AUTO_TEST_CASE(legacy_capture_precedes_reindex_and_survives_repeated_planning)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    options.reindex = true;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.reindex);
    BOOST_CHECK(options.reindex_chainstate);
    BOOST_CHECK(options.fReindexGeth);
    BOOST_CHECK(fReindexGeth);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        captured = *journal.ReadUpgrade();
        BOOST_CHECK(captured.genesis_hash == consensus.hashGenesisBlock);
        BOOST_CHECK_EQUAL(captured.legacy_tip_height, 5);
        BOOST_CHECK(captured.legacy_tip_hash == hashes[5]);
        BOOST_CHECK(captured.predecessor_hash == hashes[2]);
        BOOST_REQUIRE(journal.MarkReplayReady());
    }
    {
        CDBWrapper coins{DB("chainstate")};
        uint256 best;
        BOOST_REQUIRE(coins.Read(uint8_t{'B'}, best));
        BOOST_CHECK(best == hashes[5]);
    }
    options = {};
    fReindexGeth = false;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(!options.reindex_chainstate);
    BOOST_CHECK(!options.fReindexGeth);
    {
        LOCK(cs_main);
        BOOST_CHECK(!m_node.chainman->IsPQLegacyRebuild());
        BOOST_REQUIRE(m_node.chainman->GetPQLegacyUpgrade());
        captured.phase = node::PQLegacyUpgradePhase::REPLAY_READY;
        BOOST_CHECK(*m_node.chainman->GetPQLegacyUpgrade() == captured);
    }
    options.reindex_chainstate = true;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    captured.phase = node::PQLegacyUpgradePhase::REBUILD_REQUIRED;
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
}

BOOST_AUTO_TEST_CASE(interrupted_capture_rechecks_bodies_but_replay_ready_preserves_progress)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        captured = *journal.ReadUpgrade();
    }
    fs::resize_file(BlockFile(), positions.back() + 80);
    options = {};
    fReindexGeth = false;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!options.reindex);
    BOOST_CHECK(!options.reindex_chainstate);
    BOOST_CHECK(!options.fReindexGeth);
    BOOST_CHECK(!fReindexGeth);
    {
        CDBWrapper coins{DB("chainstate")};
        uint256 best;
        BOOST_REQUIRE(coins.Read(uint8_t{'B'}, best));
        BOOST_CHECK(best == hashes.back());
    }
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        BOOST_CHECK(*journal.ReadUpgrade() == captured);
        BOOST_REQUIRE(journal.MarkReplayReady());
    }
    // Once reset preparation completed, an ordinary restart preserves replay
    // progress; it does not repeat the destructive-transition preflight.
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(!options.reindex_chainstate);
    BOOST_CHECK(!options.fReindexGeth);
    BOOST_CHECK(!fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    captured.phase = node::PQLegacyUpgradePhase::REPLAY_READY;
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
}

BOOST_AUTO_TEST_CASE(interrupted_capture_rechecks_nevm_payload_before_reset)
{
    MakeLegacy(/*height=*/5, /*with_witness=*/false, /*with_nevm=*/true);
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        captured = *journal.ReadUpgrade();
        BOOST_CHECK(captured.phase == node::PQLegacyUpgradePhase::REBUILD_REQUIRED);
    }
    CBlock corrupt{blocks[2]};
    const dev::RLP encoded{corrupt.vchNEVMBlockData};
    const auto offset{encoded[1][0][5].toBytesConstRef().data() - corrupt.vchNEVMBlockData.data()};
    corrupt.vchNEVMBlockData[offset] ^= 1;
    ReplaceNEVMPayloadOnly(2, corrupt);
    options = {};
    fReindexGeth = false;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(!options.reindex);
    BOOST_CHECK(!options.reindex_chainstate);
    BOOST_CHECK(!options.fReindexGeth);
    BOOST_CHECK(!fReindexGeth);
    {
        CDBWrapper coins{DB("chainstate")};
        uint256 best;
        BOOST_REQUIRE(coins.Read(uint8_t{'B'}, best));
        BOOST_CHECK(best == hashes.back());
    }
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
}

BOOST_AUTO_TEST_CASE(interrupted_capture_accepts_intact_suffix_with_reset_validity)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        captured = *journal.ReadUpgrade();
    }
    {
        LOCK(cs_main);
        node::BlockTreeDB db{DB("blocks/index")};
        for (int32_t height{consensus.nPQActivationHeight}; height < static_cast<int32_t>(hashes.size()); ++height) {
            CDiskBlockIndex index;
            const auto key{std::pair{uint8_t{'b'}, hashes[height]}};
            BOOST_REQUIRE(db.Read(key, index));
            // ResetPQLegacyUpgradeSuffix can already have invalidated the old
            // suffix's cached validation before the original coins are erased.
            index.nStatus &= ~(BLOCK_VALID_MASK | BLOCK_FAILED_MASK | BLOCK_CONFLICT_CHAINLOCK);
            index.nStatus |= BLOCK_VALID_TREE;
            BOOST_REQUIRE(db.Write(key, index, true));
        }
    }
    options = {};
    fReindexGeth = false;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.reindex_chainstate);
    BOOST_CHECK(options.fReindexGeth);
    BOOST_CHECK(fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
}

BOOST_AUTO_TEST_CASE(interrupted_reset_without_original_coins_or_index_resumes)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.ReadUpgrade());
        captured = *journal.ReadUpgrade();
    }
    {
        CDBWrapper coins{DB("chainstate")};
        BOOST_REQUIRE(coins.Erase(uint8_t{'B'}, true));
    }
    BOOST_REQUIRE(fs::remove_all(Path("blocks/index")) > 0);
    options = {};
    fReindexGeth = false;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(options.reindex_chainstate);
    BOOST_CHECK(options.fReindexGeth);
    BOOST_CHECK(fReindexGeth);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
}

BOOST_AUTO_TEST_CASE(pre_nevm_legacy_tip_can_be_captured_at_exact_boundary)
{
    consensus.nNEVMStartBlock = 10;
    MakeLegacy(2);
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_REQUIRE(journal.ReadUpgrade());
    BOOST_CHECK(journal.ReadUpgrade()->legacy_tip_hash ==
                journal.ReadUpgrade()->predecessor_hash);
}

BOOST_AUTO_TEST_CASE(fresh_disabled_replay_is_permanently_marked)
{
    consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_CHECK(journal.HasBLSFreeHistory());
        BOOST_CHECK(!journal.ReadUpgrade());
    }
    consensus.nPQActivationHeight = 3;
    MakeLegacy();
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    BOOST_CHECK(!options.reindex_chainstate);
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_CHECK(!journal.ReadUpgrade());
}

BOOST_AUTO_TEST_CASE(legacy_disabled_or_early_upgrade_does_not_capture_or_mark_origin)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("configured activation") != std::string::npos);
    CheckUncapturedAndUnchanged();
    consensus.nPQActivationHeight = 10;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("has not reached") != std::string::npos);
    CheckUncapturedAndUnchanged();
}

BOOST_AUTO_TEST_CASE(pruned_or_missing_physical_history_fails_before_capture)
{
    MakeLegacy();
    {
        node::BlockTreeDB db{DB("blocks/index")};
        BOOST_REQUIRE(db.WriteFlag("prunedblockfiles", true));
    }
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("was pruned") != std::string::npos);
    CheckUncapturedAndUnchanged();
    {
        node::BlockTreeDB db{DB("blocks/index")};
        BOOST_REQUIRE(db.WriteFlag("prunedblockfiles", false));
    }
    BOOST_REQUIRE(fs::remove(BlockFile()));
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("block file is missing") != std::string::npos);
    CheckUncapturedAndUnchanged();
}

BOOST_AUTO_TEST_CASE(interrupted_or_malformed_coins_and_snapshot_fail_before_capture)
{
    MakeLegacy();
    {
        CDBWrapper coins{DB("chainstate")};
        BOOST_REQUIRE(coins.Write(uint8_t{'H'}, std::vector{hashes[5], hashes[4]}, true));
    }
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("interrupted flush") != std::string::npos);
    CheckUncapturedAndUnchanged();
    {
        CDBWrapper coins{DB("chainstate")};
        BOOST_REQUIRE(coins.Write(uint8_t{'H'}, uint8_t{255}, true));
    }
    BOOST_CHECK(!Plan(options, error));
    CheckUncapturedAndUnchanged();
    {
        CDBWrapper coins{DB("chainstate")};
        BOOST_REQUIRE(coins.Erase(uint8_t{'H'}, true));
        CDBWrapper dmn{DB("evodb_dmn")};
        BOOST_REQUIRE(dmn.Write(hashes.back(),
            CDeterministicMNList{hashes[4], 4, 0}, true));
    }
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("masternode snapshot") != std::string::npos);
    CheckUncapturedAndUnchanged();
}

BOOST_AUTO_TEST_CASE(unvalidated_legacy_ancestor_cannot_authorize_upgrade)
{
    MakeLegacy();
    for (const auto flag : {BLOCK_ASSUMED_VALID, BLOCK_CONFLICT_CHAINLOCK}) {
        {
            LOCK(cs_main);
            node::BlockTreeDB db{DB("blocks/index")};
            CDiskBlockIndex index;
            BOOST_REQUIRE(db.Read(std::pair{uint8_t{'b'}, hashes[2]}, index));
            index.nStatus &= ~(BLOCK_ASSUMED_VALID | BLOCK_CONFLICT_CHAINLOCK);
            index.nStatus |= flag;
            BOOST_REQUIRE(db.Write(std::pair{uint8_t{'b'}, hashes[2]}, index, true));
        }
        node::ChainstateLoadOptions options;
        bilingual_str error;
        BOOST_CHECK(!Plan(options, error));
        CheckUncapturedAndUnchanged();
    }
}

BOOST_AUTO_TEST_CASE(snapshot_chainstate_cannot_capture_background_legacy_provenance)
{
    MakeLegacy();
    BOOST_REQUIRE(fs::create_directory(Path("chainstate_snapshot")));
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_CHECK(!Plan(options, error));
    BOOST_CHECK(error.original.find("snapshot chainstate") != std::string::npos);
    CheckUncapturedAndUnchanged();
}

BOOST_AUTO_TEST_CASE(saved_deployment_mismatch_preserves_replay_ready_record)
{
    MakeLegacy();
    node::ChainstateLoadOptions options;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(Plan(options, error), error.original);
    node::PQLegacyUpgradeRecord captured;
    {
        node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
        BOOST_REQUIRE(journal.MarkReplayReady());
        captured = *journal.ReadUpgrade();
    }
    consensus.nPQActivationHeight = 4;
    options = {};
    options.reindex = true;
    BOOST_CHECK(!Plan(options, error));
    node::PQLegacyUpgradeJournal journal{DB("pq-upgrade")};
    BOOST_CHECK(*journal.ReadUpgrade() == captured);
    BOOST_CHECK(!options.reindex_chainstate);
}

BOOST_AUTO_TEST_CASE(mixed_memory_fixture_does_not_create_upgrade_database)
{
    node::ChainstateLoadOptions options;
    bilingual_str error;
    options.coins_db_in_memory = true;
    BOOST_REQUIRE(Plan(options, error));
    BOOST_CHECK(!fs::exists(Path("pq-upgrade")));
    options.coins_db_in_memory = false;
    options.block_tree_db_in_memory = true;
    BOOST_REQUIRE(Plan(options, error));
    BOOST_CHECK(!fs::exists(Path("pq-upgrade")));
}

BOOST_AUTO_TEST_SUITE_END()
