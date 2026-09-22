// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/pq_migration_config.h>
#include <node/miner.h>
#include <node/pq_activation_handoff.h>
#include <streams.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <initializer_list>

BOOST_AUTO_TEST_SUITE(pq_migration_tests)

BOOST_AUTO_TEST_CASE(quarantine_blocks_every_template_creation_path)
{
    BOOST_CHECK(node::ShouldCreateBlockTemplate(
        /*pq_participation_allowed=*/true));
    BOOST_CHECK(!node::ShouldCreateBlockTemplate(
        /*pq_participation_allowed=*/false));
}

BOOST_AUTO_TEST_CASE(block_production_requires_authenticated_handoff)
{
    BOOST_CHECK(!node::IsPQActivationBlockProductionAllowed(
        /*participation_allowed=*/false));
    BOOST_CHECK(node::IsPQActivationBlockProductionAllowed(
        /*participation_allowed=*/true));
}

BOOST_AUTO_TEST_CASE(activation_handoff_record_serialization_is_canonical)
{
    constexpr int32_t activation_height{100};
    const uint256 predecessor{uint256::ONEV};
    const auto roundtrip = [](const node::PQActivationHandoffRecord& record) {
        CDataStream encoded{SER_DISK, PROTOCOL_VERSION};
        encoded << record;
        node::PQActivationHandoffRecord decoded;
        encoded >> decoded;
        return decoded;
    };

    for (const auto& record : {
             node::PQActivationHandoffRecord{
                 node::PQActivationHandoffRecord::VERSION,
                 node::PQActivationHandoffState::HISTORICAL_REPLAY,
                 activation_height, {}},
             node::PQActivationHandoffRecord{
                 node::PQActivationHandoffRecord::VERSION,
                 node::PQActivationHandoffState::PINNED,
                 activation_height, predecessor},
             node::PQActivationHandoffRecord{
                 node::PQActivationHandoffRecord::VERSION,
                 node::PQActivationHandoffState::FAILED,
                 activation_height, {}}}) {
        const auto decoded{roundtrip(record)};
        BOOST_CHECK_EQUAL(decoded.version, record.version);
        BOOST_CHECK(decoded.state == record.state);
        BOOST_CHECK_EQUAL(decoded.activation_height,
                          record.activation_height);
        BOOST_CHECK(decoded.predecessor_hash == record.predecessor_hash);
        BOOST_CHECK(decoded.IsValid(activation_height));
    }

    CDataStream invalid_state{SER_DISK, PROTOCOL_VERSION};
    invalid_state << node::PQActivationHandoffRecord::VERSION << uint8_t{4}
                  << activation_height << uint256{};
    node::PQActivationHandoffRecord decoded_invalid_state;
    BOOST_CHECK_THROW(invalid_state >> decoded_invalid_state,
                      std::ios_base::failure);

    auto invalid_version{node::PQActivationHandoffRecord{
        node::PQActivationHandoffRecord::VERSION + 1,
        node::PQActivationHandoffState::HISTORICAL_REPLAY,
        activation_height, {}}};
    BOOST_CHECK(!roundtrip(invalid_version).IsValid(activation_height));

    auto historical_with_hash{node::PQActivationHandoffRecord{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::HISTORICAL_REPLAY,
        activation_height, predecessor}};
    BOOST_CHECK(!historical_with_hash.IsValid(activation_height));
    auto pinned_without_hash{node::PQActivationHandoffRecord{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::PINNED,
        activation_height, {}}};
    BOOST_CHECK(!pinned_without_hash.IsValid(activation_height));
}

BOOST_AUTO_TEST_CASE(disabled_activation_preserves_legacy_replay)
{
    Consensus::Params params;
    params.DIP0003Height = 10;

    BOOST_CHECK(
        Consensus::CheckPQActivationConfiguration(params) ==
        Consensus::PQActivationResult::DISABLED);
    BOOST_CHECK(!Consensus::IsPQProviderMempoolTransitionTip(params, 10));
    for (const int height : {9, 10, 11, 1'000'000}) {
        BOOST_CHECK(
            Consensus::CheckPQLegacyReplay(params, height) ==
            Consensus::PQLegacyReplayResult::ALLOWED);
        BOOST_CHECK(
            Consensus::CheckPQPaymentEligibility(params, height) ==
            Consensus::PQPaymentEligibilityResult::LEGACY);
    }
}

BOOST_AUTO_TEST_CASE(activation_before_dip3_is_invalid)
{
    Consensus::Params params;
    params.DIP0003Height = 10;
    params.nPQActivationHeight = 9;

    BOOST_CHECK(
        Consensus::CheckPQActivationConfiguration(params) ==
        Consensus::PQActivationResult::INVALID_CONFIGURATION);
    BOOST_CHECK(!Consensus::IsPQProviderMempoolTransitionTip(params, 8));
    for (const int height : {8, 9, 10}) {
        BOOST_CHECK(
            Consensus::CheckPQLegacyReplay(params, height) ==
            Consensus::PQLegacyReplayResult::INVALID_CONFIGURATION);
        BOOST_CHECK(
            Consensus::CheckPQPaymentEligibility(params, height) ==
            Consensus::PQPaymentEligibilityResult::INVALID_CONFIGURATION);
    }
}

BOOST_AUTO_TEST_CASE(genesis_activation_is_invalid)
{
    Consensus::Params params;
    params.DIP0003Height = 0;
    params.nPQActivationHeight = 0;

    BOOST_CHECK(
        Consensus::CheckPQActivationConfiguration(params) ==
        Consensus::PQActivationResult::INVALID_CONFIGURATION);
}

BOOST_AUTO_TEST_CASE(first_pq_block_has_exact_height_boundary)
{
    Consensus::Params params;
    params.DIP0003Height = 10;
    constexpr int activation_height{100};
    params.nPQActivationHeight = activation_height;

    BOOST_REQUIRE(
        Consensus::CheckPQActivationConfiguration(params) ==
        Consensus::PQActivationResult::VALID);

    BOOST_CHECK(
        Consensus::CheckPQLegacyReplay(params, activation_height - 1) ==
        Consensus::PQLegacyReplayResult::ALLOWED);
    BOOST_CHECK(
        Consensus::CheckPQLegacyReplay(params, activation_height) ==
        Consensus::PQLegacyReplayResult::RETIRED);
    BOOST_CHECK(
        Consensus::CheckPQLegacyReplay(params, activation_height + 1) ==
        Consensus::PQLegacyReplayResult::RETIRED);

    BOOST_CHECK(
        Consensus::CheckPQPaymentEligibility(
            params, activation_height - 1) ==
        Consensus::PQPaymentEligibilityResult::LEGACY);
    BOOST_CHECK(
        Consensus::CheckPQPaymentEligibility(params, activation_height) ==
        Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED);
    BOOST_CHECK(
        Consensus::CheckPQPaymentEligibility(
            params, activation_height + 1) ==
        Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED);

    BOOST_CHECK(!Consensus::IsPQProviderMempoolTransitionTip(
        params, activation_height - 2));
    BOOST_CHECK(Consensus::IsPQProviderMempoolTransitionTip(
        params, activation_height - 1));
    BOOST_CHECK(!Consensus::IsPQProviderMempoolTransitionTip(
        params, activation_height));
}

BOOST_AUTO_TEST_CASE(activation_height_must_not_be_a_superblock)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 2'305;
    params.nSuperblockStartBlock = 1;
    params.nSuperblockCycle = 10;
    params.nNEVMStartBlock = 2'050;
    BOOST_CHECK(Consensus::IsPQActivationHeightCompatibleWithSuperblocks(
        params));

    params.nPQActivationHeight = 2'310;
    BOOST_CHECK(!Consensus::IsPQActivationHeightCompatibleWithSuperblocks(
        params));

    params.nPQActivationHeight = 100;
    params.nNEVMStartBlock = 200;
    BOOST_CHECK(!Consensus::IsPQActivationHeightCompatibleWithSuperblocks(
        params));

    params.nSuperblockCycle = 0;
    BOOST_CHECK(!Consensus::IsPQActivationHeightCompatibleWithSuperblocks(
        params));
}

BOOST_AUTO_TEST_CASE(dip3_block_can_be_the_first_pq_block)
{
    Consensus::Params params;
    params.DIP0003Height = 10;
    params.nPQActivationHeight = params.DIP0003Height;

    BOOST_REQUIRE(
        Consensus::CheckPQActivationConfiguration(params) ==
        Consensus::PQActivationResult::VALID);
    BOOST_CHECK(
        Consensus::CheckPQLegacyReplay(params, 9) ==
        Consensus::PQLegacyReplayResult::ALLOWED);
    BOOST_CHECK(
        Consensus::CheckPQLegacyReplay(params, 10) ==
        Consensus::PQLegacyReplayResult::RETIRED);
    BOOST_CHECK(
        Consensus::CheckPQPaymentEligibility(params, 10) ==
        Consensus::PQPaymentEligibilityResult::ROOT_REQUIRED);
}

BOOST_AUTO_TEST_CASE(public_activation_requires_imported_predecessor)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    const uint256 predecessor{uint256::ONEV};

    const auto prepared{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/false, std::nullopt)};
    BOOST_CHECK(prepared.state ==
                node::PQActivationRuntimeState::DEFERRED_HANDOFF);
    BOOST_CHECK(!prepared.record_to_write);

    node::PQActivationHandoffTip at_predecessor{
        /*height=*/8, predecessor, predecessor,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false};
    const auto not_imported{node::FinalizePQActivationHandoff(
        params, prepared.state, std::nullopt, at_predecessor)};
    BOOST_CHECK(not_imported.state ==
                node::PQActivationRuntimeState::DEFERRED_HANDOFF);
    BOOST_CHECK(!not_imported.record_to_write);

    at_predecessor.height = 7;
    const auto too_early{node::FinalizePQActivationHandoff(
        params, prepared.state, std::nullopt, at_predecessor)};
    BOOST_CHECK(too_early.state ==
                node::PQActivationRuntimeState::DEFERRED_HANDOFF);
    BOOST_CHECK(!too_early.record_to_write);

    at_predecessor.height = 9;
    const auto legacy_past_activation{node::FinalizePQActivationHandoff(
        params, prepared.state, std::nullopt, at_predecessor)};
    BOOST_REQUIRE(legacy_past_activation.record_to_write);
    BOOST_CHECK(legacy_past_activation.state ==
                node::PQActivationRuntimeState::FAILED);

    at_predecessor.activation_fully_validated = true;
    const auto no_record_past_activation{
        node::FinalizePQActivationHandoff(
            params, prepared.state, std::nullopt, at_predecessor)};
    BOOST_REQUIRE(no_record_past_activation.record_to_write);
    BOOST_CHECK(no_record_past_activation.state ==
                node::PQActivationRuntimeState::FAILED);

    const node::PQActivationHandoffRecord imported{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::PINNED,
        params.nPQActivationHeight, predecessor};
    const auto restored_past_activation{node::FinalizePQActivationHandoff(
        params, prepared.state, imported, at_predecessor)};
    BOOST_CHECK(restored_past_activation.state ==
                node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(!restored_past_activation.record_to_write);
}

BOOST_AUTO_TEST_CASE(activation_handoff_uses_only_active_or_connecting_tip)
{
    BOOST_CHECK(node::IsPQActivationHandoffActiveView(
        /*candidate_is_active_tip=*/true,
        /*candidate_extends_active_tip=*/false));
    BOOST_CHECK(node::IsPQActivationHandoffActiveView(
        /*candidate_is_active_tip=*/false,
        /*candidate_extends_active_tip=*/true));
    BOOST_CHECK(!node::IsPQActivationHandoffActiveView(
        /*candidate_is_active_tip=*/false,
        /*candidate_extends_active_tip=*/false));
}

BOOST_AUTO_TEST_CASE(historical_replay_never_self_promotes)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    const uint256 predecessor{uint256::ONEV};

    const auto prepared{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/true,
        /*empty_chainstate=*/false, std::nullopt)};
    BOOST_REQUIRE(prepared.record_to_write);
    BOOST_CHECK(prepared.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);

    node::PQActivationHandoffTip tip{
        /*height=*/8, predecessor, predecessor,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false};
    auto resolution{node::FinalizePQActivationHandoff(
        params, prepared.state, prepared.record_to_write, tip)};
    BOOST_CHECK(resolution.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!resolution.record_to_write);

    tip.height = 9;
    resolution = node::FinalizePQActivationHandoff(
        params, prepared.state, prepared.record_to_write, tip);
    BOOST_CHECK(resolution.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!resolution.record_to_write);

    tip.activation_fully_validated = true;
    resolution = node::FinalizePQActivationHandoff(
        params, prepared.state, prepared.record_to_write, tip);
    BOOST_CHECK(resolution.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!resolution.record_to_write);
}

BOOST_AUTO_TEST_CASE(pinned_handoff_rejects_replacement_predecessor)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    const uint256 predecessor{uint256::ONEV};
    const uint256 other{uint256::TWOV};
    const node::PQActivationHandoffRecord pinned{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::PINNED,
        params.nPQActivationHeight, predecessor};

    const auto prepared{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/false, pinned)};
    BOOST_CHECK(prepared.state ==
                node::PQActivationRuntimeState::DEFERRED_HANDOFF);
    node::PQActivationHandoffTip matching_tip{
        /*height=*/9, predecessor, predecessor,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/true};
    const auto restored{node::FinalizePQActivationHandoff(
        params, prepared.state, pinned, matching_tip)};
    BOOST_CHECK(restored.state == node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(!restored.record_to_write);

    // This BLS-free process cannot authenticate a replacement A-1, including
    // one exposed by crash recovery before block A was published.
    node::PQActivationHandoffTip recovered_replacement{
        /*height=*/8, other, other,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false};
    const auto crash_recovery{node::FinalizePQActivationHandoff(
        params, prepared.state, pinned, recovered_replacement)};
    BOOST_REQUIRE(crash_recovery.record_to_write);
    BOOST_CHECK(crash_recovery.state ==
                node::PQActivationRuntimeState::FAILED);
    BOOST_CHECK(crash_recovery.record_to_write->state ==
                node::PQActivationHandoffState::FAILED);
    BOOST_CHECK(crash_recovery.record_to_write->predecessor_hash ==
                predecessor);

    matching_tip.active_predecessor_hash = other;
    const auto mismatched_active_branch{node::FinalizePQActivationHandoff(
        params, prepared.state, pinned, matching_tip)};
    BOOST_REQUIRE(mismatched_active_branch.record_to_write);
    BOOST_CHECK(mismatched_active_branch.state ==
                node::PQActivationRuntimeState::FAILED);

    BOOST_CHECK(node::DisconnectCrossesPQActivationHandoff(
        params, node::PQActivationRuntimeState::PINNED, pinned,
        /*disconnect_height=*/8, predecessor));
    BOOST_CHECK(!node::DisconnectCrossesPQActivationHandoff(
        params, node::PQActivationRuntimeState::PINNED, pinned,
        /*disconnect_height=*/9, other));
    BOOST_CHECK(!node::DisconnectCrossesPQActivationHandoff(
        params, node::PQActivationRuntimeState::PINNED, pinned,
        /*disconnect_height=*/8, other));

    BOOST_CHECK(!node::IsPQActivationBlockProductionAllowed(
        /*participation_allowed=*/false));
}

BOOST_AUTO_TEST_CASE(unassigned_public_is_sync_only_and_regtest_bypasses)
{
    Consensus::Params params;
    params.DIP0003Height = 5;

    const auto public_unassigned{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/false, std::nullopt)};
    BOOST_CHECK(public_unassigned.state ==
                node::PQActivationRuntimeState::SYNC_ONLY);
    BOOST_CHECK(!public_unassigned.record_to_write);

    params.nPQActivationHeight = 9;
    const node::PQActivationHandoffRecord failed{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::FAILED,
        params.nPQActivationHeight, {}};
    const auto regtest{node::PreparePQActivationHandoff(
        params, /*public_network=*/false,
        /*force_historical_replay=*/true,
        /*empty_chainstate=*/true, failed)};
    BOOST_CHECK(regtest.state == node::PQActivationRuntimeState::BYPASS);
    BOOST_CHECK(!regtest.record_to_write);

    const auto reindex{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/true,
        /*empty_chainstate=*/false, failed)};
    BOOST_REQUIRE(reindex.record_to_write);
    BOOST_CHECK(reindex.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(reindex.record_to_write->state ==
                node::PQActivationHandoffState::HISTORICAL_REPLAY);
}

BOOST_AUTO_TEST_CASE(release_bootstrap_requires_assigned_valid_activation)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    for (const int height : {std::numeric_limits<int>::max(), -1, 0, 4}) {
        params.nPQActivationHeight = height;
        BOOST_CHECK(Consensus::CheckPQActivationConfiguration(params) ==
                    Consensus::PQActivationResult::INVALID_CONFIGURATION);
        const auto prepared{node::PreparePQActivationHandoff(
            params, /*public_network=*/true,
            /*force_historical_replay=*/true,
            /*empty_chainstate=*/true, std::nullopt)};
        BOOST_CHECK(prepared.state == node::PQActivationRuntimeState::FAILED);
        BOOST_CHECK(!prepared.record_to_write);
    }
    params.nPQActivationHeight = 9;
    BOOST_CHECK(Consensus::CheckPQActivationConfiguration(params) ==
                Consensus::PQActivationResult::VALID);
}

BOOST_AUTO_TEST_CASE(release_bootstrap_requires_complete_active_replay)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    const auto prepared{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/true, std::nullopt)};
    BOOST_REQUIRE(prepared.record_to_write);
    BOOST_CHECK(prepared.state == node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(prepared.record_to_write->predecessor_hash.IsNull());

    const node::PQActivationHandoffTip verified{
        /*height=*/8, uint256::ONEV, uint256::ONEV,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false,
        /*bootstrap_replay_verified=*/true};
    for (int missing_evidence = 0; missing_evidence < 5; ++missing_evidence) {
        auto tip{verified};
        switch (missing_evidence) {
        case 0: tip.height = 7; break;
        case 1: tip.predecessor_fully_validated = false; break;
        case 2: tip.active_predecessor_hash = uint256::TWOV; break;
        case 3: tip.predecessor_hash.SetNull(); break;
        case 4: tip.bootstrap_replay_verified = false; break;
        }
        const auto resolution{node::FinalizePQActivationHandoff(
            params, prepared.state, prepared.record_to_write, tip)};
        BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::HISTORICAL_REPLAY);
        BOOST_CHECK(!resolution.record_to_write);
    }

    // No certificate, live quorum or activation block is required to
    // authenticate the completed legacy replay against a release checkpoint.
    const auto resolution{node::FinalizePQActivationHandoff(
        params, prepared.state, prepared.record_to_write, verified)};
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::PINNED);
    BOOST_REQUIRE(resolution.record_to_write);
    BOOST_CHECK(resolution.record_to_write->state == node::PQActivationHandoffState::PINNED);
    BOOST_CHECK(resolution.record_to_write->IsValid(params.nPQActivationHeight));
    BOOST_CHECK(resolution.record_to_write->predecessor_hash == params.hashPQLegacyBootstrapBlock);
}

BOOST_AUTO_TEST_CASE(later_release_can_authenticate_existing_historical_replay)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    const node::PQActivationHandoffRecord historical{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::HISTORICAL_REPLAY, 9, {}};
    node::PQActivationHandoffTip tip{
        /*height=*/10, uint256::ONEV, uint256::ONEV,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/true,
        /*bootstrap_replay_verified=*/true};
    auto resolution{node::FinalizePQActivationHandoff(
        params, node::PQActivationRuntimeState::HISTORICAL_REPLAY, historical, tip)};
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!resolution.record_to_write);

    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    const auto restarted{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/false, historical)};
    BOOST_CHECK(restarted.state == node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!restarted.record_to_write);
    tip.activation_fully_validated = false;
    resolution = node::FinalizePQActivationHandoff(params, restarted.state, historical, tip);
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!resolution.record_to_write);

    tip.activation_fully_validated = true;
    resolution = node::FinalizePQActivationHandoff(params, restarted.state, historical, tip);
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::PINNED);
    BOOST_REQUIRE(resolution.record_to_write);
    BOOST_CHECK(resolution.record_to_write->predecessor_hash == uint256::ONEV);
}

BOOST_AUTO_TEST_CASE(release_bootstrap_rejects_wrong_branch_without_rewriting_authority)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    const node::PQActivationHandoffRecord historical{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::HISTORICAL_REPLAY, 9, {}};
    node::PQActivationHandoffTip tip{
        /*height=*/8, uint256::TWOV, uint256::TWOV,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false,
        /*bootstrap_replay_verified=*/true};
    auto resolution{node::FinalizePQActivationHandoff(
        params, node::PQActivationRuntimeState::HISTORICAL_REPLAY, historical, tip)};
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::FAILED);
    BOOST_CHECK(!resolution.record_to_write);

    // A rejected candidate must not poison the durable journal. Restarting
    // with the correct fully replayed branch can still authenticate it.
    tip.predecessor_hash = tip.active_predecessor_hash = uint256::ONEV;
    resolution = node::FinalizePQActivationHandoff(
        params, node::PQActivationRuntimeState::HISTORICAL_REPLAY, historical, tip);
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::PINNED);
    BOOST_REQUIRE(resolution.record_to_write);
    BOOST_CHECK(resolution.record_to_write->predecessor_hash == uint256::ONEV);
}

BOOST_AUTO_TEST_CASE(release_bootstrap_preserves_corrupt_failed_or_conflicting_records)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    const node::PQActivationHandoffTip tip{
        /*height=*/8, uint256::ONEV, uint256::ONEV,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false,
        /*bootstrap_replay_verified=*/true};
    for (const auto& record : {
             node::PQActivationHandoffRecord{2, node::PQActivationHandoffState::PINNED, 9, uint256::ONEV},
             node::PQActivationHandoffRecord{1, node::PQActivationHandoffState::PINNED, 10, uint256::ONEV},
             node::PQActivationHandoffRecord{1, node::PQActivationHandoffState::PINNED, 9, uint256::TWOV},
             node::PQActivationHandoffRecord{1, node::PQActivationHandoffState::PINNED, 9, {}},
             node::PQActivationHandoffRecord{1, node::PQActivationHandoffState::FAILED, 9, uint256::ONEV},
             node::PQActivationHandoffRecord{1, node::PQActivationHandoffState::HISTORICAL_REPLAY, 9, uint256::ONEV}}) {
        for (const bool force_replay : {false, true}) {
            for (const bool empty_chainstate : {false, true}) {
                const auto prepared{node::PreparePQActivationHandoff(
                    params, /*public_network=*/true,
                    force_replay, empty_chainstate, record)};
                BOOST_CHECK(prepared.state == node::PQActivationRuntimeState::FAILED);
                BOOST_CHECK(!prepared.record_to_write);
            }
        }
        for (const auto runtime : {node::PQActivationRuntimeState::HISTORICAL_REPLAY,
                                   node::PQActivationRuntimeState::DEFERRED_HANDOFF}) {
            const auto resolution{node::FinalizePQActivationHandoff(params, runtime, record, tip)};
            BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::FAILED);
            BOOST_CHECK(!resolution.record_to_write);
        }
    }
}

BOOST_AUTO_TEST_CASE(release_bootstrap_restart_and_reindex_reestablish_readiness)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    params.hashPQLegacyBootstrapBlock = uint256::ONEV;
    const node::PQActivationHandoffRecord pinned{
        node::PQActivationHandoffRecord::VERSION,
        node::PQActivationHandoffState::PINNED, 9, uint256::ONEV};
    node::PQActivationHandoffTip tip{
        /*height=*/9, uint256::ONEV, uint256::ONEV,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/true,
        /*bootstrap_replay_verified=*/true};
    for (const bool force_replay : {false, true}) {
        for (const bool empty_chainstate : {false, true}) {
            const auto prepared{node::PreparePQActivationHandoff(
                params, /*public_network=*/true,
                force_replay, empty_chainstate, pinned)};
            BOOST_CHECK(prepared.state == (force_replay || empty_chainstate
                ? node::PQActivationRuntimeState::HISTORICAL_REPLAY
                : node::PQActivationRuntimeState::DEFERRED_HANDOFF));
            BOOST_CHECK(!prepared.record_to_write);
            auto incomplete{tip};
            incomplete.bootstrap_replay_verified = false;
            auto resolution{node::FinalizePQActivationHandoff(
                params, prepared.state, pinned, incomplete)};
            BOOST_CHECK(resolution.state == prepared.state);
            BOOST_CHECK(!resolution.record_to_write);
            resolution = node::FinalizePQActivationHandoff(params, prepared.state, pinned, tip);
            BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::PINNED);
            BOOST_CHECK(!resolution.record_to_write);
        }
    }
    BOOST_CHECK(node::DisconnectCrossesPQActivationHandoff(
        params, node::PQActivationRuntimeState::PINNED, pinned, 8, uint256::ONEV));
    // Once durable, the authenticated pin remains consumable by a release
    // without the optional anchor; it does not need new certificate rules.
    params.hashPQLegacyBootstrapBlock.SetNull();
    const auto restored{node::FinalizePQActivationHandoff(
        params, node::PQActivationRuntimeState::DEFERRED_HANDOFF, pinned, tip)};
    BOOST_CHECK(restored.state == node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(!restored.record_to_write);
}

BOOST_AUTO_TEST_SUITE_END()
