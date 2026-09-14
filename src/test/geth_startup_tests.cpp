// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/geth_startup.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <map>
#include <string>

using node::GethStartupWaitState;

namespace {

void WriteGethTestFile(const fs::path& path, const std::string& contents)
{
    fs::create_directories(path.parent_path());
    std::ofstream file{path, std::ios::binary};
    BOOST_REQUIRE(file.is_open());
    file << contents;
    file.close();
    BOOST_REQUIRE(!file.fail());
}

// Include empty directories and symlinks as well as every byte of regular files.
std::map<std::string, std::string> GethFileInventory(const fs::path& root)
{
    std::map<std::string, std::string> inventory;
    if (!fs::exists(root)) return inventory;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        const std::string name{fs::PathToString(entry.path().lexically_relative(root))};
        const auto status{entry.symlink_status()};
        if (fs::is_symlink(status)) {
            inventory.emplace(name, "symlink:" + fs::PathToString(fs::read_symlink(entry.path())));
        } else if (fs::is_directory(status)) {
            inventory.emplace(name, "directory");
        } else {
            BOOST_REQUIRE(fs::is_regular_file(status));
            std::ifstream file{entry.path(), std::ios::binary};
            BOOST_REQUIRE(file.is_open());
            const std::string contents{std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
            BOOST_REQUIRE(!file.bad());
            inventory.emplace(name, "file:" + contents);
        }
    }
    return inventory;
}

void WriteProtectedGethFiles(const fs::path& root)
{
    WriteGethTestFile(root / "geth/keystore/key-a", "synthetic wallet key A\n");
    WriteGethTestFile(root / "geth/keystore/nested/key-b", "synthetic wallet key B\n");
    WriteGethTestFile(root / "geth/geth/nodekey", "synthetic modern node key\n");
    WriteGethTestFile(root / "geth/nodekey", "synthetic legacy node key\n");
    WriteGethTestFile(root / "geth/geth/jwtsecret", "synthetic modern JWT secret\n");
    WriteGethTestFile(root / "geth/jwtsecret", "synthetic legacy JWT secret\n");
    WriteGethTestFile(root / "geth/geth/custom-file", "unknown instance data\n");
    WriteGethTestFile(root / "geth/custom-dir/backup", "unknown user data\n");
}

void CheckAmbiguousGethBackup(const fs::path& root)
{
    const auto before{GethFileInventory(root)};
    for (const bool reindex : {false, true}) {
        std::string error;
        BOOST_CHECK(!node::PrepareGethDataDirectory(root, reindex, error));
        BOOST_CHECK(!error.empty());
        BOOST_CHECK(error.find("key") != std::string::npos);
        BOOST_CHECK(GethFileInventory(root) == before);
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE(geth_startup_tests)

BOOST_AUTO_TEST_CASE(bootstrap_completion_starts_fresh_normal_timeout)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    BOOST_CHECK(wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{66}).count(), 64);
    BOOST_CHECK(!wait.Expired(start + Seconds{66}));

    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{72});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{101}).count(), 29);
    BOOST_CHECK(!wait.Expired(start + Seconds{101}));
    BOOST_CHECK(wait.Expired(start + Seconds{102}));
}

BOOST_AUTO_TEST_CASE(bootstrap_status_flicker_does_not_consume_final_completion_grace)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{72});
    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{73});
    BOOST_CHECK(wait.BootstrapActive());

    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{200});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK_EQUAL(wait.ActiveElapsed(start + Seconds{229}).count(), 29);
    BOOST_CHECK(!wait.Expired(start + Seconds{229}));
    BOOST_CHECK(wait.Expired(start + Seconds{230}));
}

BOOST_AUTO_TEST_CASE(dead_geth_does_not_gain_post_bootstrap_grace)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds{30}, Seconds{7200}};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/false, start + Seconds{20});
    BOOST_CHECK(!wait.BootstrapActive());
    BOOST_CHECK(wait.Expired(start + Seconds{30}));
}

BOOST_AUTO_TEST_CASE(zero_timeout_remains_unbounded)
{
    using Seconds = GethStartupWaitState::Seconds;
    const GethStartupWaitState::Clock::time_point start{};
    GethStartupWaitState wait{start, Seconds::zero(), Seconds::zero()};

    wait.Observe(/*bootstrap_status_present=*/true, /*geth_running=*/true, start + Seconds{2});
    BOOST_CHECK(!wait.Expired(start + Seconds{100000}));
    wait.Observe(/*bootstrap_status_present=*/false, /*geth_running=*/true, start + Seconds{100001});
    BOOST_CHECK(!wait.Expired(start + Seconds{200000}));
}

BOOST_FIXTURE_TEST_CASE(reindex_preserves_keys_and_unknown_files_in_place, BasicTestingSetup)
{
    const fs::path root{m_path_root / "geth-reset"};
    WriteProtectedGethFiles(root);
    const auto protected_files{GethFileInventory(root)};
    WriteGethTestFile(root / "geth/geth/chaindata/CURRENT", "modern database\n");
    WriteGethTestFile(root / "geth/geth/chaindata/ancient/chain/header.0000.cdat", "ancient blocks\n");
    WriteGethTestFile(root / "geth/chaindata/CURRENT", "legacy database\n");
    const auto original_files{GethFileInventory(root)};

    std::string error;
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/false, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(GethFileInventory(root) == original_files);

    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(GethFileInventory(root) == protected_files);
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(GethFileInventory(root) == protected_files);

    // Retry after an interrupted database removal left only a subtree behind.
    WriteGethTestFile(root / "geth/geth/chaindata/ancient/chain/body.0000.cdat", "remaining ancient blocks\n");
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(GethFileInventory(root) == protected_files);
}

BOOST_FIXTURE_TEST_CASE(reindex_with_no_key_material_does_not_create_keys, BasicTestingSetup)
{
    const fs::path root{m_path_root / "geth-empty-reset"};
    std::string error;
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/false, error));
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(!fs::exists(root));

    WriteGethTestFile(root / "geth/geth/chaindata/CURRENT", "database without keys\n");
    BOOST_REQUIRE(node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(!fs::exists(root / "geth/geth/chaindata"));
    BOOST_CHECK(!fs::exists(root / "geth/keystore"));
    BOOST_CHECK(!fs::exists(root / "geth/geth/nodekey"));
    BOOST_CHECK(!fs::exists(root / "geth/nodekey"));
}

BOOST_FIXTURE_TEST_CASE(legacy_key_backups_block_startup_and_reindex_without_changes, BasicTestingSetup)
{
    for (const std::string backup_name : {"keystoretmp", "nodekeytmp"}) {
        for (const std::string scenario : {"partial_backup", "backup_only", "partial_restore", "empty_backup"}) {
            BOOST_TEST_CONTEXT(backup_name << ": " << scenario) {
                const fs::path root{m_path_root / fs::u8path(backup_name + "-" + scenario)};
                const bool wallet{backup_name == "keystoretmp"};
                const fs::path original{root / (wallet ? "geth/keystore/key-a" : "geth/geth/nodekey")};
                const fs::path backup{root / fs::u8path(backup_name)};
                if (scenario != "backup_only") {
                    WriteGethTestFile(original, scenario == "partial_restore" ? "partial key" : "complete original key");
                    if (wallet && scenario != "partial_restore") {
                        WriteGethTestFile(original.parent_path() / "key-b", "second original key");
                    }
                }
                if (wallet) {
                    fs::create_directories(backup);
                    if (scenario != "empty_backup") {
                        WriteGethTestFile(backup / "key-a", scenario == "partial_backup" ? "partial key" : "complete original key");
                        if (scenario != "partial_backup") WriteGethTestFile(backup / "key-b", "second original key");
                    }
                } else {
                    WriteGethTestFile(backup, scenario == "empty_backup" ? "" :
                        scenario == "partial_backup" ? "partial key" : "complete original key");
                }
                WriteGethTestFile(root / "geth/geth/chaindata/CURRENT", "must remain untouched\n");
                CheckAmbiguousGethBackup(root);
            }
        }
    }
}

#ifndef WIN32
BOOST_FIXTURE_TEST_CASE(dangling_legacy_key_backup_links_block_startup_and_reindex, BasicTestingSetup)
{
    for (const std::string backup_name : {"keystoretmp", "nodekeytmp"}) {
        BOOST_TEST_CONTEXT(backup_name) {
            const fs::path root{m_path_root / fs::u8path("dangling-" + backup_name)};
            WriteProtectedGethFiles(root);
            WriteGethTestFile(root / "geth/geth/chaindata/CURRENT", "must remain untouched\n");
            fs::create_symlink("missing-recovery-target", root / fs::u8path(backup_name));
            CheckAmbiguousGethBackup(root);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(reindex_refuses_symlinked_geth_ancestor_without_touching_target, BasicTestingSetup)
{
    for (const bool instance_link : {false, true}) {
        BOOST_TEST_CONTEXT((instance_link ? "instance directory" : "Geth data directory")) {
            const fs::path root{m_path_root / (instance_link ? "instance-link" : "datadir-link")};
            const fs::path core_datadir{root / "core"};
            const fs::path target{root / "external"};
            const fs::path link{core_datadir / (instance_link ? "geth/geth" : "geth")};
            WriteGethTestFile(target / "keystore/key-a", "complete wallet key\n");
            WriteGethTestFile(target / "nodekey", "complete node key\n");
            WriteGethTestFile(target / "chaindata/CURRENT", "database behind symlink\n");
            WriteGethTestFile(target / "geth/chaindata/CURRENT", "nested database behind symlink\n");
            fs::create_directories(link.parent_path());
            fs::create_directory_symlink(target, link);
            const auto original_files{GethFileInventory(root)};

            std::string error;
            BOOST_CHECK(!node::PrepareGethDataDirectory(core_datadir, /*reindex=*/true, error));
            BOOST_CHECK(!error.empty());
            BOOST_CHECK(GethFileInventory(root) == original_files);
            BOOST_CHECK(fs::is_symlink(fs::symlink_status(link)));
            BOOST_CHECK(fs::read_symlink(link) == target);
        }
    }
}
#endif

BOOST_FIXTURE_TEST_CASE(reindex_filesystem_error_preserves_key_material, BasicTestingSetup)
{
    const fs::path root{m_path_root / "geth-reset-error"};
    WriteGethTestFile(root / "geth/keystore/key-a", "complete wallet key\n");
    WriteGethTestFile(root / "geth/nodekey", "complete node key\n");
    // A non-directory ancestor makes removing geth/geth/chaindata fail.
    WriteGethTestFile(root / "geth/geth", "unexpected file\n");
    const auto original_files{GethFileInventory(root)};
    std::string error;
    BOOST_CHECK(!node::PrepareGethDataDirectory(root, /*reindex=*/true, error));
    BOOST_CHECK(!error.empty());
    BOOST_CHECK(GethFileInventory(root) == original_files);
}

BOOST_AUTO_TEST_SUITE_END()
