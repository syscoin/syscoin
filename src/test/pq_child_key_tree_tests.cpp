// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_child_key_derivation.h>
#include <llmq/pq_child_key_tree.h>

#include <clientversion.h>
#include <hash.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <vector>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value == 0 ? 1 : value;
    return hash;
}

ChainLockMasterSeed TestSeed()
{
    ChainLockMasterSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0x80 + i);
    }
    return seed;
}

ChildKeyTreeConfig TestConfig()
{
    return {
        .genesis_hash = NonNullHash(1),
        .tree_id = NonNullHash(2),
        .generation = 1,
        .first_epoch = 100,
        .depth = 4,
    };
}

constexpr uint16_t TEST_CACHE_VERSION{1};
constexpr std::string_view TEST_CACHE_DOMAIN{"SYS_PQ_CHILD_TREE_CACHE_V1"};

uint256 CacheChecksum(const ChildKeyTreeConfig& config,
                      const uint256& root,
                      const std::vector<uint256>& nodes)
{
    CHashWriter writer{SER_GETHASH, 0};
    writer.write(AsBytes(Span{TEST_CACHE_DOMAIN.data(),
                              TEST_CACHE_DOMAIN.size()}));
    writer << TEST_CACHE_VERSION << config.genesis_hash << config.tree_id
           << config.generation << config.first_epoch << config.depth << root
           << static_cast<uint32_t>(nodes.size());
    for (const auto& node : nodes) writer << node;
    return writer.GetHash();
}

bool RewriteCacheWithValidChecksum(const fs::path& path,
                                   const ChildKeyTreeConfig& config,
                                   const uint256& root,
                                   const std::vector<uint256>& nodes)
{
    try {
        CAutoFile file{fsbridge::fopen(path, "wb"), CLIENT_VERSION};
        if (file.IsNull()) return false;
        file << TEST_CACHE_VERSION << config.genesis_hash << config.tree_id
             << config.generation << config.first_epoch << config.depth << root
             << static_cast<uint32_t>(nodes.size());
        for (const auto& node : nodes) file << node;
        file << CacheChecksum(config, root, nodes);
        file.fclose();
        return true;
    } catch (...) {
        return false;
    }
}

std::optional<std::vector<uint256>> ReadCacheNodes(const fs::path& path)
{
    try {
        CAutoFile file{fsbridge::fopen(path, "rb"), CLIENT_VERSION};
        if (file.IsNull()) return std::nullopt;
        uint16_t version{0};
        ChildKeyTreeConfig config;
        uint256 root;
        uint32_t node_count{0};
        file >> version >> config.genesis_hash >> config.tree_id
             >> config.generation >> config.first_epoch >> config.depth
             >> root >> node_count;
        if (version != TEST_CACHE_VERSION || node_count == 0 ||
            node_count > 2 * (std::size_t{1} << CHILD_KEY_TREE_MAX_DEPTH) - 1) {
            return std::nullopt;
        }
        std::vector<uint256> nodes(node_count);
        for (auto& node : nodes) file >> node;
        return nodes;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_child_key_tree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(configuration_bounds_are_exact)
{
    BOOST_CHECK_GE(DefaultChildKeyTreeWorkerCount(), 1U);
    BOOST_CHECK_LE(DefaultChildKeyTreeWorkerCount(),
                   CHILD_KEY_TREE_MAX_WORKERS);

    auto config{TestConfig()};
    BOOST_REQUIRE(config.IsValid());
    BOOST_CHECK_EQUAL(config.LeafCount(), 16U);
    BOOST_CHECK(config.EpochAt(0) == 100);
    BOOST_CHECK(config.EpochAt(15) == 115);
    BOOST_CHECK(!config.EpochAt(16));
    BOOST_CHECK(config.IndexForEpoch(100) == 0);
    BOOST_CHECK(config.IndexForEpoch(115) == 15);
    BOOST_CHECK(!config.IndexForEpoch(99));
    BOOST_CHECK(!config.IndexForEpoch(116));

    config.genesis_hash.SetNull();
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.tree_id.SetNull();
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.generation = 0;
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.generation = CHILD_KEY_TREE_MAX_GENERATION;
    BOOST_CHECK(config.IsValid());
    config.generation = CHILD_KEY_TREE_MAX_GENERATION + 1;
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.depth = 0;
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.depth = CHILD_KEY_TREE_MAX_DEPTH + 1;
    BOOST_CHECK(!config.IsValid());
    config = TestConfig();
    config.depth = CHILD_KEY_TREE_MAX_DEPTH;
    config.first_epoch = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(serial_and_parallel_roots_match_and_all_paths_verify)
{
    const auto seed{TestSeed()};
    const auto config{TestConfig()};
    auto serial{ChildKeyTree::Build(seed, config, 1)};
    auto parallel{ChildKeyTree::Build(seed, config, 4)};
    BOOST_REQUIRE(serial);
    BOOST_REQUIRE(parallel);
    BOOST_CHECK(serial->GetRoot() == parallel->GetRoot());
    BOOST_CHECK_EQUAL(serial->CacheBytes(), (2 * config.LeafCount() - 1) * 32);

    for (std::size_t index{0}; index < config.LeafCount(); ++index) {
        const auto epoch{config.EpochAt(index)};
        BOOST_REQUIRE(epoch);
        const auto public_key{DeriveCommittedChildPublicKey(
            seed, config.genesis_hash, config.tree_id, config.generation,
            *epoch)};
        BOOST_REQUIRE(public_key);
        const auto proof{serial->GetProof(*public_key, *epoch)};
        BOOST_REQUIRE(proof);
        BOOST_CHECK_EQUAL(proof->siblings.size(), config.depth);
        BOOST_CHECK(VerifyChildKeyTreeProof(
            config, serial->GetRoot(), *epoch, *proof));
    }
}

BOOST_AUTO_TEST_CASE(proofs_are_bound_to_every_tree_and_leaf_field)
{
    const auto seed{TestSeed()};
    const auto config{TestConfig()};
    auto tree{ChildKeyTree::Build(seed, config, 2)};
    BOOST_REQUIRE(tree);
    const uint32_t epoch{107};
    const auto public_key{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation, epoch)};
    BOOST_REQUIRE(public_key);
    auto proof{tree->GetProof(*public_key, epoch)};
    BOOST_REQUIRE(proof);
    BOOST_REQUIRE(VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));

    auto wrong_public_key{*public_key};
    wrong_public_key[0] ^= 1;
    BOOST_CHECK(!tree->GetProof(wrong_public_key, epoch));
    BOOST_CHECK(!tree->GetProof(*public_key, config.first_epoch - 1));
    BOOST_CHECK(!tree->GetProof(*public_key, epoch + 1));

    auto changed_config{config};
    changed_config.tree_id = NonNullHash(9);
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        changed_config, tree->GetRoot(), epoch, *proof));
    changed_config = config;
    ++changed_config.generation;
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        changed_config, tree->GetRoot(), epoch, *proof));
    changed_config = config;
    --changed_config.first_epoch;
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        changed_config, tree->GetRoot(), epoch, *proof));
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch + 1, *proof));
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, NonNullHash(8), epoch, *proof));

    proof->public_key[0] ^= 1;
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));
    proof = tree->GetProof(*public_key, epoch);
    BOOST_REQUIRE(proof);
    proof->siblings[0].begin()[0] ^= 1;
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));
    proof = tree->GetProof(*public_key, epoch);
    BOOST_REQUIRE(proof);
    proof->siblings.pop_back();
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));
    proof = tree->GetProof(*public_key, epoch);
    BOOST_REQUIRE(proof);
    proof->siblings.push_back(NonNullHash(7));
    BOOST_CHECK(!VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));
}

BOOST_AUTO_TEST_CASE(committed_kdf_is_domain_generation_and_epoch_bound)
{
    const auto seed{TestSeed()};
    const auto config{TestConfig()};
    const auto first{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation, 100)};
    const auto replay{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation, 100)};
    const auto next_generation{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation + 1, 100)};
    const auto next_epoch{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation, 101)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(replay);
    BOOST_REQUIRE(next_generation);
    BOOST_REQUIRE(next_epoch);
    BOOST_CHECK(*first == *replay);
    BOOST_CHECK(*first != *next_generation);
    BOOST_CHECK(*first != *next_epoch);

    BOOST_CHECK(!DeriveCommittedChildPublicKey(
        seed, uint256{}, config.tree_id, config.generation, 100));
    BOOST_CHECK(!DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, uint256{}, config.generation, 100));
    BOOST_CHECK(!DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, 0, 100));
    BOOST_CHECK(!DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id,
        CHILD_KEY_TREE_MAX_GENERATION + 1, 100));
}

BOOST_AUTO_TEST_CASE(cache_rejects_rechecksummed_noncanonical_tree)
{
    const auto seed{TestSeed()};
    const auto config{TestConfig()};
    auto tree{ChildKeyTree::Build(seed, config, 4)};
    BOOST_REQUIRE(tree);
    const fs::path path{m_path_root / "pq_child_tree.cache"};
    BOOST_REQUIRE(tree->Save(path));

    auto loaded{ChildKeyTree::Load(path, config, tree->GetRoot())};
    BOOST_REQUIRE(loaded);
    const uint32_t epoch{config.first_epoch + 7};
    const auto public_key{DeriveCommittedChildPublicKey(
        seed, config.genesis_hash, config.tree_id, config.generation, epoch)};
    BOOST_REQUIRE(public_key);
    const auto proof{loaded->GetProof(*public_key, epoch)};
    BOOST_REQUIRE(proof);
    BOOST_CHECK(VerifyChildKeyTreeProof(
        config, tree->GetRoot(), epoch, *proof));

    auto nodes{ReadCacheNodes(path)};
    BOOST_REQUIRE(nodes);
    BOOST_REQUIRE(nodes->size() > 2);
    (*nodes)[1].begin()[0] ^= 1;
    BOOST_REQUIRE(RewriteCacheWithValidChecksum(
        path, config, tree->GetRoot(), *nodes));
    BOOST_CHECK(!ChildKeyTree::Load(path, config, tree->GetRoot()));
}

BOOST_AUTO_TEST_SUITE_END()
