// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pq_legacy_database.h>

#include <dbwrapper.h>
#include <services/assetconsensus.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pq_legacy_database_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legacy_root_schema_is_read_only_and_obfuscation_aware)
{
    for (const bool obfuscate : {false, true}) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "legacy_roots",
                       .cache_bytes = 1 << 20,
                       .memory_only = true,
                       .obfuscate = obfuscate}};
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::EMPTY);
        BOOST_CHECK(!db.Exists(uint8_t{'V'}));

        const NEVMTxRoot first{uint256{11}, uint256{12}};
        const NEVMTxRoot second{uint256{21}, uint256{22}};
        BOOST_REQUIRE(db.Write(uint256{1}, first));
        BOOST_REQUIRE(db.Write(uint256{2}, second));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::LEGACY);
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::LEGACY);
        BOOST_CHECK(!db.Exists(uint8_t{'V'}));
        NEVMTxRoot retained;
        BOOST_REQUIRE(db.Read(uint256{1}, retained));
        BOOST_CHECK(retained.nTxRoot == first.nTxRoot);
        BOOST_CHECK(retained.nReceiptRoot == first.nReceiptRoot);
        BOOST_REQUIRE(db.Read(uint256{2}, retained));
        BOOST_CHECK(retained.nTxRoot == second.nTxRoot);
        BOOST_CHECK(retained.nReceiptRoot == second.nReceiptRoot);
    }
}

BOOST_AUTO_TEST_CASE(current_root_schema_permits_typed_records)
{
    for (const bool obfuscate : {false, true}) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "current_roots",
                       .cache_bytes = 1 << 20,
                       .memory_only = true,
                       .obfuscate = obfuscate}};
        const NEVMRootUndo undo{uint256{1}, uint256{2}, NEVMTxRoot{}, std::nullopt};
        BOOST_REQUIRE(db.Write(std::pair{uint8_t{'U'}, uint256{3}}, undo));
        BOOST_REQUIRE(db.Write(uint8_t{'T'}, uint256{3}));
        BOOST_REQUIRE(db.Write(uint8_t{'V'}, uint32_t{1}));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CURRENT);
    }
}

BOOST_AUTO_TEST_CASE(missing_schema_with_typed_or_unknown_keys_is_not_legacy)
{
    const auto check_key = [&](const auto& key) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "mixed_roots",
                       .cache_bytes = 1 << 20,
                       .memory_only = true}};
        BOOST_REQUIRE(db.Write(uint256{1}, NEVMTxRoot{}));
        BOOST_REQUIRE(db.Write(key, NEVMTxRoot{}));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CORRUPT);
        BOOST_CHECK(!db.Exists(uint8_t{'V'}));
    };
    check_key(std::pair{uint8_t{'U'}, uint256{2}});
    check_key(uint8_t{'T'});
    check_key(uint8_t{'D'});
    check_key(std::string{"unknown"});
    check_key(std::array<uint8_t, 31>{});
    check_key(std::array<uint8_t, 33>{});
    check_key(std::pair{uint8_t{'V'}, uint8_t{0}});
}

BOOST_AUTO_TEST_CASE(schema_version_requires_exact_supported_encoding)
{
    const auto check_value = [&](const auto& value) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "malformed_schema",
                       .cache_bytes = 1 << 20,
                       .memory_only = true}};
        BOOST_REQUIRE(db.Write(uint256{1}, NEVMTxRoot{}));
        BOOST_REQUIRE(db.Write(uint8_t{'V'}, value));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CORRUPT);
    };
    check_value(uint32_t{0});
    check_value(uint32_t{2});
    check_value(uint8_t{1});
    check_value(std::array<uint8_t, 0>{});
    check_value(std::pair{uint32_t{1}, uint8_t{0}});
}

BOOST_AUTO_TEST_CASE(legacy_roots_reject_truncated_or_extended_values)
{
    const auto check_value = [&](const auto& value) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "malformed_root",
                       .cache_bytes = 1 << 20,
                       .memory_only = true}};
        BOOST_REQUIRE(db.Write(uint256{1}, NEVMTxRoot{}));
        BOOST_REQUIRE(db.Write(uint256{2}, value));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CORRUPT);
    };
    check_value(uint256{2});
    check_value(std::array<uint8_t, 63>{});
    check_value(std::array<uint8_t, 65>{});
    check_value(std::pair{NEVMTxRoot{}, uint8_t{0}});
}

BOOST_AUTO_TEST_CASE(obfuscation_metadata_requires_exact_encoding)
{
    const std::string metadata_key{"\0obfuscate_key", 14};
    for (const std::size_t size : {0, 7, 9}) {
        CDBWrapper db{{.path = m_args.GetDataDirBase() / "malformed_obfuscation",
                       .cache_bytes = 1 << 20,
                       .memory_only = true}};
        BOOST_REQUIRE(db.Write(uint256{1}, NEVMTxRoot{}));
        // std::string serialization adds its own one-byte length prefix.
        BOOST_REQUIRE(db.Write(metadata_key, std::string(size, '\0')));
        BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CORRUPT);
    }
    CDBWrapper db{{.path = m_args.GetDataDirBase() / "wrong_obfuscation_prefix",
                   .cache_bytes = 1 << 20,
                   .memory_only = true}};
    // Nine physical bytes are insufficient if the vector length is wrong.
    std::array<uint8_t, 9> malformed{7};
    BOOST_REQUIRE(db.Write(metadata_key, malformed));
    BOOST_CHECK(node::InspectNEVMRootSchema(db) == node::NEVMRootSchema::CORRUPT);
}

BOOST_AUTO_TEST_SUITE_END()
