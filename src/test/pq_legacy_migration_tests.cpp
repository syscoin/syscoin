// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_migration.h>

#include <chain.h>
#include <consensus/params.h>
#include <dbwrapper.h>
#include <evo/deterministicmns.h>
#include <flatfile.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <node/pq_legacy_upgrade.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

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

    void MakeLegacy(int32_t height = 5)
    {
        LOCK(cs_main);
        hashes.push_back(consensus.hashGenesisBlock);
        for (int32_t h{1}; h <= height; ++h) {
            hashes.emplace_back(static_cast<uint8_t>(h));
        }
        fs::create_directories(BlockFile().parent_path());
        {
            std::ofstream file{BlockFile(), std::ios::binary};
            const std::string bytes(static_cast<std::size_t>(height + 1) * 128, '\0');
            file.write(bytes.data(), bytes.size());
            BOOST_REQUIRE(file.good());
        }
        {
            node::BlockTreeDB db{DB("blocks/index")};
            for (int32_t h{0}; h <= height; ++h) {
                CDiskBlockIndex index;
                index.nHeight = h;
                index.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
                index.nFile = 0;
                index.nDataPos = static_cast<unsigned int>(h) * 128;
                index.nTx = 1;
                index.hashPrev = h == 0 ? uint256{} : hashes[h - 1];
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
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_legacy_migration_tests, LegacyMigrationSetup)

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
