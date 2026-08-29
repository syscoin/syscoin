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

BOOST_AUTO_TEST_CASE(historical_replay_can_produce_only_activation_block)
{
    Consensus::Params params;
    params.DIP0003Height = 5;
    params.nPQActivationHeight = 9;
    const auto allowed = [&](node::PQActivationRuntimeState state,
                             int32_t tip_height,
                             bool tip_valid = true,
                             bool local_state = true,
                             bool durable_finality_clear = true,
                             bool durable_marker = true) {
        return node::IsPQActivationBlockProductionAllowed(
            params, state, /*participation_allowed=*/false,
            durable_marker, tip_height, tip_valid, local_state,
            durable_finality_clear);
    };

    // Fresh/reindex replay reaches A-1 with a durable null marker. The
    // replacement transition into this same predicate is covered below.
    BOOST_CHECK(allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 8));

    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 7));
    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 9));
    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 8,
                         /*tip_valid=*/false));
    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 8,
                         /*tip_valid=*/true, /*local_state=*/false));
    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 8,
                         /*tip_valid=*/true, /*local_state=*/true,
                         /*durable_finality_clear=*/false));
    BOOST_CHECK(!allowed(node::PQActivationRuntimeState::HISTORICAL_REPLAY, 8,
                         /*tip_valid=*/true, /*local_state=*/true,
                         /*durable_finality_clear=*/true,
                         /*durable_marker=*/false));
    for (const auto state : {
             node::PQActivationRuntimeState::SYNC_ONLY,
             node::PQActivationRuntimeState::DEFERRED_HANDOFF,
             node::PQActivationRuntimeState::FAILED}) {
        BOOST_CHECK(!allowed(state, 8));
    }

    BOOST_CHECK(node::IsPQActivationBlockProductionAllowed(
        params, node::PQActivationRuntimeState::FAILED,
        /*participation_allowed=*/true,
        /*durable_replay_marker=*/false, /*active_tip_height=*/-1,
        /*active_tip_fully_validated=*/false,
        /*local_state_usable=*/false, /*durable_finality_clear=*/false));
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

BOOST_AUTO_TEST_CASE(public_activation_handoff_requires_validated_predecessor)
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
    const auto pinned{node::FinalizePQActivationHandoff(
        params, prepared.state, std::nullopt, at_predecessor)};
    BOOST_REQUIRE(pinned.record_to_write);
    BOOST_CHECK(pinned.state == node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(pinned.record_to_write->state ==
                node::PQActivationHandoffState::PINNED);
    BOOST_CHECK_EQUAL(pinned.record_to_write->activation_height, 9);
    BOOST_CHECK(pinned.record_to_write->predecessor_hash == predecessor);

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

    const auto restored_past_activation{node::FinalizePQActivationHandoff(
        params, prepared.state, pinned.record_to_write, at_predecessor)};
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

BOOST_AUTO_TEST_CASE(historical_replay_unlocks_only_after_validating_activation)
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
    BOOST_REQUIRE(resolution.record_to_write);
    BOOST_CHECK(resolution.state == node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(resolution.record_to_write->predecessor_hash == predecessor);
}

BOOST_AUTO_TEST_CASE(pinned_handoff_is_sticky_only_at_exact_predecessor)
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

    // The block-tree pin is fsynced before ConnectTip publishes A. If a crash
    // rolls chainstate back below A-1, reaching a different valid A-1 must
    // reproduce the normal pre-finality quarantine transition rather than
    // turning the local pin into a hash checkpoint.
    node::PQActivationHandoffTip recovered_replacement{
        /*height=*/8, other, other,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false};
    const auto crash_recovery{node::FinalizePQActivationHandoff(
        params, prepared.state, pinned, recovered_replacement)};
    BOOST_REQUIRE(crash_recovery.record_to_write);
    BOOST_CHECK(crash_recovery.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(crash_recovery.record_to_write->state ==
                node::PQActivationHandoffState::HISTORICAL_REPLAY);
    BOOST_CHECK(crash_recovery.record_to_write->predecessor_hash.IsNull());

    const auto recovery_waits_at_predecessor{
        node::FinalizePQActivationHandoff(
            params, crash_recovery.state, crash_recovery.record_to_write,
            recovered_replacement)};
    BOOST_CHECK(recovery_waits_at_predecessor.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!recovery_waits_at_predecessor.record_to_write);
    recovered_replacement.height = 9;
    recovered_replacement.activation_fully_validated = true;
    const auto recovered_pin{node::FinalizePQActivationHandoff(
        params, crash_recovery.state, crash_recovery.record_to_write,
        recovered_replacement)};
    BOOST_REQUIRE(recovered_pin.record_to_write);
    BOOST_CHECK(recovered_pin.state ==
                node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(recovered_pin.record_to_write->predecessor_hash == other);

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

    const auto quarantined{node::ResolvePQActivationHandoffDisconnect(
        params, node::PQActivationRuntimeState::PINNED, pinned,
        /*disconnect_height=*/8, predecessor)};
    BOOST_REQUIRE(quarantined.record_to_write);
    BOOST_CHECK(quarantined.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(quarantined.record_to_write->state ==
                node::PQActivationHandoffState::HISTORICAL_REPLAY);
    BOOST_CHECK(node::IsPQActivationBlockProductionAllowed(
        params, quarantined.state, /*participation_allowed=*/false,
        quarantined.record_to_write->IsValid(params.nPQActivationHeight),
        /*active_tip_height=*/8, /*active_tip_fully_validated=*/true,
        /*local_state_usable=*/true, /*durable_finality_clear=*/true));
    BOOST_CHECK(quarantined.record_to_write->predecessor_hash.IsNull());

    const auto unrelated_disconnect{
        node::ResolvePQActivationHandoffDisconnect(
            params, node::PQActivationRuntimeState::PINNED, pinned,
            /*disconnect_height=*/8, other)};
    BOOST_CHECK(unrelated_disconnect.state ==
                node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(!unrelated_disconnect.record_to_write);

    // A crash at any point after the durable quarantine restarts without the
    // old hash. The replacement A-1 alone cannot unlock participation; full
    // validation of its block A successor establishes the replacement pin.
    const auto restarted{node::PreparePQActivationHandoff(
        params, /*public_network=*/true,
        /*force_historical_replay=*/false,
        /*empty_chainstate=*/false, quarantined.record_to_write)};
    BOOST_CHECK(restarted.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!restarted.record_to_write);

    node::PQActivationHandoffTip replacement_tip{
        /*height=*/8, other, other,
        /*predecessor_fully_validated=*/true,
        /*activation_fully_validated=*/false};
    auto replacement{node::FinalizePQActivationHandoff(
        params, restarted.state, quarantined.record_to_write,
        replacement_tip)};
    BOOST_CHECK(replacement.state ==
                node::PQActivationRuntimeState::HISTORICAL_REPLAY);
    BOOST_CHECK(!replacement.record_to_write);

    replacement_tip.height = 9;
    replacement_tip.activation_fully_validated = true;
    replacement = node::FinalizePQActivationHandoff(
        params, restarted.state, quarantined.record_to_write,
        replacement_tip);
    BOOST_REQUIRE(replacement.record_to_write);
    BOOST_CHECK(replacement.state ==
                node::PQActivationRuntimeState::PINNED);
    BOOST_CHECK(replacement.record_to_write->state ==
                node::PQActivationHandoffState::PINNED);
    BOOST_CHECK(replacement.record_to_write->predecessor_hash == other);
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

BOOST_AUTO_TEST_SUITE_END()
