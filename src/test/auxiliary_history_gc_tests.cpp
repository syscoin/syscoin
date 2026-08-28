// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/auxiliary_history_gc.h>
#include <evo/deterministicmns.h>

#include <chainparams.h>
#include <test/util/setup_common.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>

#include <boost/test/unit_test.hpp>

namespace {

uint256 TestHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<unsigned char>(value >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

evo::AuxiliaryHistoryGCDeployment TestDeployment(uint64_t salt = 1)
{
    return {TestHash(salt), TestHash(salt + 1)};
}

DBParams TestDBParams(const fs::path& path, bool wipe)
{
    return DBParams{
        .path = path,
        .cache_bytes = 1 << 20,
        .memory_only = false,
        .wipe_data = wipe,
    };
}

evo::AuxiliaryHistoryGCComponent Component(uint64_t position,
                                           unsigned char closure_byte)
{
    return evo::AuxiliaryHistoryGCComponent{
        /*version=*/1, position, {closure_byte}};
}

evo::AuxiliaryHistoryGCIntentTarget Target(
    int32_t authorization_height,
    uint64_t dmn_position,
    std::optional<uint64_t> pq_position = std::nullopt)
{
    evo::AuxiliaryHistoryGCIntentTarget target;
    target.authorization = {
        evo::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {authorization_height,
         TestHash(static_cast<uint64_t>(authorization_height) + 100)}};
    target.frontier.dmn = Component(
        dmn_position, static_cast<unsigned char>(dmn_position));
    if (pq_position) {
        target.frontier.pq_registry = Component(
            *pq_position, static_cast<unsigned char>(*pq_position));
        // SYSCOIN: Versioned empty is the exact canonical manifest for a PQ
        // frontier advance that has no physical keys to erase.
        target.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
            /*version=*/1, {}};
    }
    return target;
}

struct TrailingDiskKey {
    uint8_t type{1};
    uint8_t trailing{0};

    SERIALIZE_METHODS(TrailingDiskKey, obj)
    {
        READWRITE(obj.type, obj.trailing);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(auxiliary_history_gc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(intent_survives_restart_and_completion_is_atomic)
{
    const fs::path base{m_path_root / "aux_gc_restart"};
    const auto deployment{TestDeployment()};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto target{Target(/*authorization_height=*/100,
                             /*dmn_position=*/80,
                             /*pq_position=*/64)};
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_CHECK(journal.IsHealthy());
        BOOST_CHECK(journal.GetState().watermark == std::nullopt);
        BOOST_CHECK(journal.GetState().intent == std::nullopt);
        BOOST_CHECK(journal.Begin(target, &intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_CHECK(!intent_id.IsNull());
        BOOST_REQUIRE(journal.GetState().intent);
        BOOST_CHECK(journal.GetState().intent->target == target);
    }

    params.wipe_data = false;
    {
        evo::AuxiliaryHistoryGCJournal resumed{params, deployment};
        const auto state{resumed.GetState()};
        BOOST_REQUIRE(state.intent);
        BOOST_CHECK(state.intent->intent_id == intent_id);
        BOOST_CHECK(resumed.HighestAuthorization() ==
                    target.authorization);
        uint256 replay_id;
        BOOST_CHECK(resumed.Begin(target, &replay_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::EXISTING);
        BOOST_CHECK(replay_id == intent_id);
        BOOST_CHECK(resumed.Complete(intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }

    {
        evo::AuxiliaryHistoryGCJournal completed{params, deployment};
        const auto state{completed.GetState()};
        BOOST_CHECK(!state.intent);
        BOOST_REQUIRE(state.watermark);
        BOOST_CHECK(state.watermark->frontier == target.frontier);
        BOOST_CHECK(state.watermark->completed_intent_id == intent_id);
        BOOST_CHECK(completed.Complete(intent_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE);
        uint256 replay_id;
        BOOST_CHECK(completed.Begin(target, &replay_id) ==
                    evo::AuxiliaryHistoryGCJournalResult::ALREADY_COMPLETE);
        BOOST_CHECK(replay_id == intent_id);
    }
}

BOOST_AUTO_TEST_CASE(begin_enforces_exact_idempotence_and_cumulative_progress)
{
    const fs::path base{m_path_root / "aux_gc_monotonic"};
    const auto deployment{TestDeployment(10)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    evo::AuxiliaryHistoryGCJournal journal{params, deployment};

    const auto first{Target(100, 80)};
    auto initial_pq_without_manifest{Target(100, 80, 1)};
    initial_pq_without_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(initial_pq_without_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT);
    auto initial_manifest_without_pq{first};
    initial_manifest_without_pq.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(initial_manifest_without_pq) ==
                evo::AuxiliaryHistoryGCJournalResult::INVALID_ARGUMENT);

    uint256 first_id;
    BOOST_REQUIRE(journal.Begin(first, &first_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::STARTED);
    BOOST_CHECK(journal.Begin(Target(101, 81)) ==
                evo::AuxiliaryHistoryGCJournalResult::BUSY);
    BOOST_CHECK(journal.Complete(TestHash(999)) ==
                evo::AuxiliaryHistoryGCJournalResult::MISMATCH);
    BOOST_REQUIRE(journal.Complete(first_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    auto same_frontier_different_authorizer{first};
    same_frontier_different_authorizer.authorization.block.height = 101;
    same_frontier_different_authorizer.authorization.block.block_hash =
        TestHash(201);
    BOOST_CHECK(journal.Begin(same_frontier_different_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto changed_equal_position{Target(101, 80)};
    changed_equal_position.frontier.dmn->closure = {42};
    BOOST_CHECK(journal.Begin(changed_equal_position) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto changed_component_version{Target(101, 81)};
    changed_component_version.frontier.dmn->version = 2;
    BOOST_CHECK(journal.Begin(changed_component_version) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto removed_component{Target(101, 81)};
    removed_component.frontier.dmn.reset();
    removed_component.frontier.pq_registry = Component(1, 1);
    removed_component.pq_erase_manifest =
        evo::AuxiliaryHistoryGCManifest{/*version=*/1, {}};
    BOOST_CHECK(journal.Begin(removed_component) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto add_pq_without_manifest{Target(101, 81, 1)};
    add_pq_without_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(add_pq_without_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    const auto second{Target(101, 81, 1)};
    uint256 second_id;
    BOOST_REQUIRE(journal.Begin(second, &second_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::STARTED);
    BOOST_REQUIRE(journal.Complete(second_id) ==
                  evo::AuxiliaryHistoryGCJournalResult::COMPLETED);

    auto same_frontier_lower_authorizer{second};
    same_frontier_lower_authorizer.authorization.block.height = 100;
    same_frontier_lower_authorizer.authorization.block.block_hash =
        TestHash(200);
    BOOST_CHECK(journal.Begin(same_frontier_lower_authorizer) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
    auto same_frontier_changed_manifest{second};
    same_frontier_changed_manifest.pq_erase_manifest->payload = {1};
    BOOST_CHECK(journal.Begin(same_frontier_changed_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);

    auto unchanged_pq_with_manifest{Target(102, 82, 1)};
    BOOST_CHECK(journal.Begin(unchanged_pq_with_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::NON_MONOTONIC);
    unchanged_pq_with_manifest.pq_erase_manifest.reset();
    BOOST_CHECK(journal.Begin(unchanged_pq_with_manifest) ==
                evo::AuxiliaryHistoryGCJournalResult::STARTED);
}

BOOST_AUTO_TEST_CASE(manager_restores_persisted_authorization_high_watermark)
{
    SelectParams(ChainType::REGTEST);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreAnchor {
        Consensus::Params& consensus;
        int32_t height{consensus.nPQChainLockAnchorHeight};
        uint256 hash{consensus.hashPQChainLockAnchorBlock};
        ~RestoreAnchor()
        {
            consensus.nPQChainLockAnchorHeight = height;
            consensus.hashPQChainLockAnchorBlock = hash;
        }
    } restore{consensus};
    const int32_t anchor_height{consensus.DIP0003Height + 10};
    consensus.nPQChainLockAnchorHeight = anchor_height;
    consensus.hashPQChainLockAnchorBlock = TestHash(500);

    const fs::path base{m_path_root / "aux_gc_manager_restore"};
    auto params{TestDBParams(base, /*wipe=*/true)};
    const auto deployment{
        evo::MakeAuxiliaryHistoryGCDeployment(consensus)};
    auto target{Target(anchor_height + 100, 80)};
    target.frontier.pq_registry = target.frontier.dmn;
    target.frontier.dmn.reset();
    target.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
        /*version=*/1, {}};
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
        BOOST_REQUIRE(journal.Begin(target, &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
        BOOST_REQUIRE(journal.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }

    params.wipe_data = false;
    CDeterministicMNManager manager{params};
    const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization lower{
        CDeterministicMNManager::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {anchor_height + 50, TestHash(650)}};
    BOOST_CHECK(!manager.UpdateAuxiliaryHistoryGCAuthorization(lower));
}

BOOST_AUTO_TEST_CASE(empty_schema_rebinds_but_durable_state_is_deployment_bound)
{
    const fs::path base{m_path_root / "aux_gc_strict"};
    const auto deployment{TestDeployment(20)};
    const evo::AuxiliaryHistoryGCDeployment rebound_deployment{
        deployment.genesis_hash, TestHash(22)};
    auto params{TestDBParams(base, /*wipe=*/true)};
    {
        evo::AuxiliaryHistoryGCJournal journal{params, deployment};
    }
    params.wipe_data = false;
    BOOST_CHECK_THROW(
        evo::AuxiliaryHistoryGCJournal(params, TestDeployment(21)),
        std::runtime_error);
    uint256 intent_id;
    {
        evo::AuxiliaryHistoryGCJournal rebound{params,
                                               rebound_deployment};
        BOOST_REQUIRE(rebound.Begin(Target(100, 80), &intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::STARTED);
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params, deployment),
                      std::runtime_error);
    {
        evo::AuxiliaryHistoryGCJournal resumed{params,
                                               rebound_deployment};
        BOOST_REQUIRE(resumed.Complete(intent_id) ==
                      evo::AuxiliaryHistoryGCJournalResult::COMPLETED);
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params, deployment),
                      std::runtime_error);

    {
        auto raw_params{params};
        raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
        CDBWrapper raw{raw_params};
        BOOST_REQUIRE(raw.Write(uint8_t{99}, uint8_t{1},
                                /*fSync=*/true));
    }
    BOOST_CHECK_THROW(evo::AuxiliaryHistoryGCJournal(params,
                                                      rebound_deployment),
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(startup_rejects_trailing_keys_and_corrupt_values)
{
    const auto deployment{TestDeployment(30)};
    {
        const fs::path base{m_path_root / "aux_gc_schema_less"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{2}, uint8_t{0},
                                    /*fSync=*/true));
        }
        params.wipe_data = false;
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }

    {
        const fs::path base{m_path_root / "aux_gc_trailing_key"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        { evo::AuxiliaryHistoryGCJournal journal{params, deployment}; }
        params.wipe_data = false;
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(TrailingDiskKey{}, uint8_t{1},
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }

    {
        const fs::path base{m_path_root / "aux_gc_corrupt_intent"};
        auto params{TestDBParams(base, /*wipe=*/true)};
        uint256 intent_id;
        {
            evo::AuxiliaryHistoryGCJournal journal{params, deployment};
            BOOST_REQUIRE(journal.Begin(Target(100, 80), &intent_id) ==
                          evo::AuxiliaryHistoryGCJournalResult::STARTED);
        }
        params.wipe_data = false;
        {
            auto raw_params{params};
            raw_params.path = evo::AuxiliaryHistoryGCDBPath(base);
            CDBWrapper raw{raw_params};
            BOOST_REQUIRE(raw.Write(uint8_t{3}, uint8_t{0},
                                    /*fSync=*/true));
        }
        BOOST_CHECK_THROW(
            evo::AuxiliaryHistoryGCJournal(params, deployment),
            std::runtime_error);
    }
}

BOOST_AUTO_TEST_SUITE_END()
