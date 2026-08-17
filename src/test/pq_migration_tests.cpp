// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/pq_migration.h>

#include <chainparams.h>
#include <common/args.h>
#include <evo/pq_registry.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

const std::string ANCHOR_BLOCK_HASH{std::string(63, '0') + "1"};
const std::string ANCHOR_DMN_STATE_HASH{std::string(63, '0') + "2"};
const std::string ANCHOR_PQ_STATE_HASH{std::string(63, '0') + "3"};

void SetPQLegacyAnchorArgs(ArgsManager& args, std::string height = "1100")
{
    args.ForceSetArg("-pqlegacyanchorheight", height);
    args.ForceSetArg("-pqlegacyanchorblockhash", ANCHOR_BLOCK_HASH);
    args.ForceSetArg("-pqlegacydmnstatehash", ANCHOR_DMN_STATE_HASH);
    args.ForceSetArg("-pqlegacypqregistrystatehash", ANCHOR_PQ_STATE_HASH);
}

} // namespace

BOOST_AUTO_TEST_SUITE(pq_migration_tests)

BOOST_AUTO_TEST_CASE(configuration_is_fail_closed)
{
    Consensus::Params params;
    BOOST_CHECK(Consensus::CheckPQLegacyAnchorConfiguration(params) ==
                Consensus::PQLegacyAnchorResult::DISABLED);
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 0, uint256::ZEROV, nullptr) ==
                Consensus::PQLegacyAnchorResult::DISABLED);

    params.nPQLegacyAnchorHeight = 10;
    BOOST_CHECK(Consensus::CheckPQLegacyAnchorConfiguration(params) ==
                Consensus::PQLegacyAnchorResult::INVALID_CONFIGURATION);
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 0, uint256::ZEROV, nullptr) ==
                Consensus::PQLegacyAnchorResult::INVALID_CONFIGURATION);

    params.DIP0003Height = 11;
    params.hashPQLegacyAnchorBlock = uint256::ONEV;
    params.hashPQLegacyMNState = uint256::TWOV;
    params.hashPQLegacyPQRegistryState = uint256S("3");
    BOOST_CHECK(Consensus::CheckPQLegacyAnchorConfiguration(params) ==
                Consensus::PQLegacyAnchorResult::INVALID_CONFIGURATION);
    params.DIP0003Height = 10;

    BOOST_CHECK(Consensus::CheckPQLegacyAnchorConfiguration(params) ==
                Consensus::PQLegacyAnchorResult::VALID);
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 9, uint256::ZEROV, nullptr) ==
                Consensus::PQLegacyAnchorResult::VALID);
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 10, uint256::TWOV, nullptr) ==
                Consensus::PQLegacyAnchorResult::BLOCK_HASH_MISMATCH);
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 10, uint256::ONEV, nullptr) ==
                Consensus::PQLegacyAnchorResult::VALID);
}

BOOST_AUTO_TEST_CASE(regtest_anchor_overrides_are_atomic_exact_and_scoped)
{
    const auto defaults = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK(
        Consensus::CheckPQLegacyAnchorConfiguration(defaults->GetConsensus()) ==
        Consensus::PQLegacyAnchorResult::DISABLED);

    ArgsManager configured;
    SetPQLegacyAnchorArgs(configured);
    configured.ForceSetArg("-pqpreparationheight", "500");
    configured.ForceSetArg("-pqchainlockepochorigin", "1440");
    configured.ForceSetArg("-pqregistrationcutoffblocks", "144");
    configured.ForceSetArg("-pqfuturehorizonepochs", "8");
    const auto params = CreateChainParams(configured, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.nPQLegacyAnchorHeight, 1100);
    BOOST_CHECK_EQUAL(consensus.hashPQLegacyAnchorBlock.GetHex(),
                      ANCHOR_BLOCK_HASH);
    BOOST_CHECK_EQUAL(consensus.hashPQLegacyMNState.GetHex(),
                      ANCHOR_DMN_STATE_HASH);
    BOOST_CHECK_EQUAL(consensus.hashPQLegacyPQRegistryState.GetHex(),
                      ANCHOR_PQ_STATE_HASH);
    BOOST_CHECK(
        Consensus::CheckPQLegacyAnchorConfiguration(consensus) ==
        Consensus::PQLegacyAnchorResult::VALID);
    llmq::pq::PQRegistryConfig registry_config;
    BOOST_CHECK(llmq::pq::GetPQRegistryConfig(consensus, registry_config) ==
                llmq::pq::PQRegistryDeploymentResult::VALID);

    BOOST_CHECK_THROW(CreateChainParams(configured, ChainType::MAIN),
                      std::runtime_error);

    ArgsManager partial;
    partial.ForceSetArg("-pqlegacyanchorheight", "1100");
    BOOST_CHECK_THROW(CreateChainParams(partial, ChainType::REGTEST),
                      std::runtime_error);

    ArgsManager malformed_hash;
    SetPQLegacyAnchorArgs(malformed_hash);
    malformed_hash.ForceSetArg("-pqlegacyanchorblockhash", "01");
    BOOST_CHECK_THROW(CreateChainParams(malformed_hash, ChainType::REGTEST),
                      std::runtime_error);

    ArgsManager non_hex_hash;
    SetPQLegacyAnchorArgs(non_hex_hash);
    non_hex_hash.ForceSetArg("-pqlegacyanchorblockhash",
                            std::string(63, '0') + "g");
    BOOST_CHECK_THROW(CreateChainParams(non_hex_hash, ChainType::REGTEST),
                      std::runtime_error);

    ArgsManager zero_hash;
    SetPQLegacyAnchorArgs(zero_hash);
    zero_hash.ForceSetArg("-pqlegacydmnstatehash", std::string(64, '0'));
    BOOST_CHECK_THROW(CreateChainParams(zero_hash, ChainType::REGTEST),
                      std::runtime_error);

    ArgsManager malformed_height;
    SetPQLegacyAnchorArgs(malformed_height, "1100x");
    BOOST_CHECK_THROW(CreateChainParams(malformed_height, ChainType::REGTEST),
                      std::runtime_error);

    ArgsManager before_dip3;
    SetPQLegacyAnchorArgs(before_dip3, "100");
    BOOST_CHECK_THROW(CreateChainParams(before_dip3, ChainType::REGTEST),
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(ancestry_and_state_are_anchored)
{
    Consensus::Params params;
    params.DIP0003Height = 0;
    params.nPQLegacyAnchorHeight = 2;
    params.hashPQLegacyAnchorBlock = uint256::ONEV;
    params.hashPQLegacyMNState = uint256::TWOV;
    params.hashPQLegacyPQRegistryState = uint256S("3");

    std::array<CBlockIndex, 4> chain;
    std::array<uint256, 4> hashes{uint256::ZEROV, uint256::ZEROV, uint256::ONEV, uint256::ZEROV};
    for (size_t i = 0; i < chain.size(); ++i) {
        chain[i].nHeight = static_cast<int>(i);
        chain[i].phashBlock = &hashes[i];
        if (i != 0) chain[i].pprev = &chain[i - 1];
        chain[i].BuildSkip();
    }

    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 3, hashes[3], &chain[2]) ==
                Consensus::PQLegacyAnchorResult::VALID);
    hashes[2] = uint256::TWOV;
    BOOST_CHECK(Consensus::CheckPQLegacyAnchor(params, 3, hashes[3], &chain[2]) ==
                Consensus::PQLegacyAnchorResult::ANCESTOR_HASH_MISMATCH);

    BOOST_CHECK(Consensus::CheckPQLegacyMNState(params, 1, uint256::ZEROV));
    BOOST_CHECK(!Consensus::CheckPQLegacyMNState(params, 2, uint256::ONEV));
    BOOST_CHECK(Consensus::CheckPQLegacyMNState(params, 2, uint256::TWOV));
    BOOST_CHECK(!Consensus::CheckPQLegacyState(
        params, 2, uint256::TWOV, uint256::ONEV));
    BOOST_CHECK(Consensus::CheckPQLegacyState(
        params, 2, uint256::TWOV, uint256S("3")));
}

BOOST_AUTO_TEST_CASE(loaded_branches_must_descend_from_anchor)
{
    Consensus::Params params;
    params.DIP0003Height = 0;
    params.nPQLegacyAnchorHeight = 2;
    params.hashPQLegacyAnchorBlock = uint256::ONEV;
    params.hashPQLegacyMNState = uint256::TWOV;
    params.hashPQLegacyPQRegistryState = uint256S("3");

    std::array<uint256, 4> good_hashes{uint256S("10"), uint256S("11"),
                                       uint256::ONEV, uint256S("13")};
    std::array<CBlockIndex, 4> good{};
    for (size_t i = 0; i < good.size(); ++i) {
        good[i].nHeight = static_cast<int>(i);
        good[i].phashBlock = &good_hashes[i];
        good[i].pprev = i == 0 ? nullptr : &good[i - 1];
        good[i].BuildSkip();
    }
    BOOST_CHECK(Consensus::IsPQLegacyAnchorCompatible(params, &good[1], &good[2]));
    BOOST_CHECK(Consensus::IsPQLegacyAnchorCompatible(params, &good[3], &good[2]));

    std::array<uint256, 4> stale_hashes{uint256S("20"), uint256S("21"),
                                        uint256S("22"), uint256S("23")};
    std::array<CBlockIndex, 4> stale{};
    for (size_t i = 0; i < stale.size(); ++i) {
        stale[i].nHeight = static_cast<int>(i);
        stale[i].phashBlock = &stale_hashes[i];
        stale[i].pprev = i == 0 ? nullptr : &stale[i - 1];
        stale[i].BuildSkip();
    }
    BOOST_CHECK(Consensus::IsPQLegacyAnchorCompatible(params, &stale[1]));
    BOOST_CHECK(!Consensus::IsPQLegacyAnchorCompatible(params, &stale[1], &good[2]));
    BOOST_CHECK(!Consensus::IsPQLegacyAnchorCompatible(params, &stale[2], &good[2]));
    BOOST_CHECK(!Consensus::IsPQLegacyAnchorCompatible(params, &stale[3], &good[2]));
}

BOOST_AUTO_TEST_CASE(known_anchor_rejects_fork_prefix_ending_immediately_before_it)
{
    Consensus::Params params;
    params.DIP0003Height = 0;
    params.nPQLegacyAnchorHeight = 3;
    params.hashPQLegacyMNState = uint256::TWOV;
    params.hashPQLegacyPQRegistryState = uint256S("3");

    std::array<uint256, 4> canonical_hashes{
        uint256S("100"), uint256S("101"), uint256S("102"), uint256S("103")};
    params.hashPQLegacyAnchorBlock = canonical_hashes.back();
    std::array<CBlockIndex, 4> canonical{};
    for (size_t i = 0; i < canonical.size(); ++i) {
        canonical[i].nHeight = static_cast<int>(i);
        canonical[i].phashBlock = &canonical_hashes[i];
        canonical[i].pprev = i == 0 ? nullptr : &canonical[i - 1];
        canonical[i].BuildSkip();
    }

    std::array<uint256, 3> fork_hashes{
        canonical_hashes[0], canonical_hashes[1], uint256S("202")};
    std::array<CBlockIndex, 3> fork{};
    for (size_t i = 0; i < fork.size(); ++i) {
        fork[i].nHeight = static_cast<int>(i);
        fork[i].phashBlock = &fork_hashes[i];
        fork[i].pprev = i == 0 ? nullptr : &fork[i - 1];
        fork[i].BuildSkip();
    }

    BOOST_CHECK(
        Consensus::CheckPQLegacyAnchor(
            params, 2, canonical_hashes[2], &canonical[1], &canonical[3]) ==
        Consensus::PQLegacyAnchorResult::VALID);
    BOOST_CHECK(
        Consensus::CheckPQLegacyAnchor(
            params, 2, fork_hashes[2], &fork[1], &canonical[3]) ==
        Consensus::PQLegacyAnchorResult::ANCESTOR_HASH_MISMATCH);
    BOOST_CHECK(!Consensus::IsPQLegacyAnchorCompatible(
        params, &fork[2], &canonical[3]));
}

BOOST_AUTO_TEST_SUITE_END()
