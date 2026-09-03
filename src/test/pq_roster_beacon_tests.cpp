// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_roster_beacon.h>

#include <streams.h>
#include <test/util/setup_common.h>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <type_traits>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

RosterBeaconSeed EmptySeed(uint32_t epoch)
{
    RosterBeaconSeed seed;
    seed.epoch = epoch;
    return seed;
}

RosterBeaconSeed PendingSeed(
    uint32_t epoch,
    uint64_t salt = 1,
    RosterBeaconAnchorKind kind = RosterBeaconAnchorKind::NORMAL)
{
    constexpr int32_t ANCHOR_TARGET{1'160};
    RosterBeaconSeed seed;
    seed.anchor_kind = kind;
    seed.state = RosterBeaconState::PENDING;
    seed.epoch = epoch;
    seed.anchor_cursor =
        BTCCursor{ANCHOR_TARGET, NonNullHash(10'000 + salt),
                  NonNullHash(20'000 + salt)};
    seed.anchor_btc_height = 800'000;
    return seed;
}

RosterBeaconSeed ReadySeed(
    uint32_t epoch,
    uint64_t salt = 1,
    RosterBeaconAnchorKind kind = RosterBeaconAnchorKind::NORMAL)
{
    auto seed{PendingSeed(epoch, salt, kind)};
    seed.state = RosterBeaconState::READY;
    seed.future_btc_hash = NonNullHash(30'000 + salt);
    return seed;
}

ActiveRosterBeaconBundle ReadyBundle(uint32_t first_epoch,
                                     uint64_t salt = 1)
{
    ActiveRosterBeaconBundle bundle;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        bundle.seeds[slot] = ReadySeed(
            first_epoch + static_cast<uint32_t>(slot), salt + slot);
    }
    bundle.recovery_authority_source.normal_beacon = bundle.seeds.back();
    return bundle;
}

RecoveryRosterAuthoritySource NormalAuthoritySource(
    uint32_t source_epoch = 40,
    uint64_t salt = 1)
{
    RecoveryRosterAuthoritySource source;
    source.normal_beacon = ReadySeed(source_epoch, salt);
    return source;
}

ActiveRosterBeaconBundle RecoveryBundle(uint32_t first_epoch,
                                        uint64_t salt = 1)
{
    const auto window{MakeRecoveryRosterBeaconWindow(
        NormalAuthoritySource(/*source_epoch=*/40, salt),
        first_epoch + static_cast<uint32_t>(ACTIVE_QUORUMS - 1))};
    BOOST_REQUIRE(window);
    return window->active;
}

RosterBeaconWindow Window(uint32_t first_epoch, uint64_t salt = 1)
{
    RosterBeaconWindow window;
    window.active = ReadyBundle(first_epoch, salt);
    window.next = EmptySeed(first_epoch + ACTIVE_QUORUMS);
    return window;
}

RosterBeaconWindow InitialNormalWindow(uint32_t first_epoch,
                                       uint64_t salt = 1)
{
    RosterBeaconWindow window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] = ReadySeed(
            first_epoch + static_cast<uint32_t>(slot), salt);
    }
    window.active.recovery_authority_source.normal_beacon =
        window.active.seeds.back();
    window.next = EmptySeed(first_epoch + ACTIVE_QUORUMS);
    return window;
}

RosterBeaconWindow RecoveryWindow(
    const RecoveryRosterAuthoritySource& source,
    uint32_t first_epoch)
{
    const auto window{MakeRecoveryRosterBeaconWindow(
        source,
        first_epoch + static_cast<uint32_t>(ACTIVE_QUORUMS - 1))};
    BOOST_REQUIRE(window);
    return *window;
}

RosterBeaconWindow RecoveryWindow(uint32_t first_epoch, uint64_t salt = 1)
{
    return RecoveryWindow(
        NormalAuthoritySource(/*source_epoch=*/40, salt),
        first_epoch);
}

RosterAuthorizationTransition Transition(
    RosterAuthorizationTransitionKind kind,
    const RosterBeaconWindow& new_window,
    std::optional<RosterAuthorizationPriorState> previous = std::nullopt)
{
    RosterAuthorizationTransition transition;
    transition.kind = kind;
    transition.target_height = 1'445;
    transition.target_block_hash = NonNullHash(50'001);
    transition.predecessor_height = 1'440;
    transition.predecessor_block_hash = NonNullHash(50'002);
    if (kind != RosterAuthorizationTransitionKind::INITIALIZE) {
        transition.authorization_base = RosterAuthorizationBaseIdentity{
            transition.predecessor_height,
            transition.predecessor_block_hash,
            NonNullHash(50'003)};
    }
    transition.previous = std::move(previous);
    transition.new_window = new_window;
    return transition;
}

RosterAuthorizationPriorState Prior(const RosterBeaconWindow& window,
                                     uint64_t salt = 1)
{
    return RosterAuthorizationPriorState{NonNullHash(60'000 + salt), window};
}

NormalRosterAuthorizationInput NormalInput(
    const RosterBeaconWindow& previous_window,
    uint32_t newest_epoch)
{
    NormalRosterAuthorizationInput input;
    input.newest_epoch = newest_epoch;
    input.target_height = 3'005;
    input.target_block_hash = NonNullHash(70'001);
    input.predecessor_height = 3'000;
    input.predecessor_block_hash = NonNullHash(70'002);
    input.authorization_base = RosterAuthorizationBaseIdentity{
        input.predecessor_height, input.predecessor_block_hash,
        NonNullHash(70'005)};
    input.previous = Prior(previous_window);
    input.previous_btcc_cursor =
        BTCCursor{2'995, NonNullHash(70'003), NonNullHash(70'004)};
    input.accepted_btcc_cursor = input.previous_btcc_cursor;
    input.next_snapshot = RosterBeaconSnapshotCoverage{
        newest_epoch + 1, input.predecessor_height + 1, {}, false};
    const bool recovery_authorized{
        HasRecoveryRosterBeacon(previous_window)};
    const auto* source{FindNewestNormalReadySeed(previous_window)};
    BOOST_REQUIRE(recovery_authorized || source != nullptr);
    input.recovery_authority_source = recovery_authorized
        ? previous_window.active.recovery_authority_source
        : RecoveryRosterAuthoritySource{*source};
    return input;
}

void CoverNextSnapshot(NormalRosterAuthorizationInput& input)
{
    input.next_snapshot.height = input.authorization_base.height;
    input.next_snapshot.hash = input.authorization_base.block_hash;
    input.next_snapshot.prior_authorization_is_descendant = true;
}

void SetAcceptedAdvance(NormalRosterAuthorizationInput& input,
                        int32_t anchor_btc_height = 900'000,
                        int32_t lag = 6)
{
    input.accepted_btcc_cursor =
        BTCCursor{input.target_height, input.target_block_hash,
                  NonNullHash(70'006)};
    input.btcc_advance = BTCCAdvance::ADVANCE;
    input.accepted_anchor = ValidatedRosterBeaconAnchor{
        input.accepted_btcc_cursor, anchor_btc_height,
        anchor_btc_height + lag, true};
}

ValidatedRosterBeaconRange RevealRange(const RosterBeaconSeed& pending,
                                       int32_t confirmations = 6)
{
    const auto future_height{pending.FutureBTCHeight()};
    if (!future_height) return {};
    return ValidatedRosterBeaconRange{
        pending.anchor_cursor.btc_hash, pending.anchor_btc_height,
        pending.IsReady() ? pending.future_btc_hash : NonNullHash(70'007),
        *future_height,
        *future_height + confirmations - 1, true};
}

template <typename T>
T RoundTrip(const T& value)
{
    DataStream stream;
    stream << value;
    T decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    return decoded;
}

using ModifierFunction = std::optional<uint256> (*)(
    const uint256&, uint32_t, int32_t, const uint256&,
    const RosterBeaconSeed&) noexcept;

// The sole modifier API has no branch-base, carrier, or handoff hash input.
static_assert(std::is_same_v<decltype(static_cast<ModifierFunction>(
                                 &GetPQQuorumModifier)),
                             ModifierFunction>);

} // namespace

BOOST_AUTO_TEST_SUITE(pq_roster_beacon_tests)

BOOST_AUTO_TEST_CASE(record_states_are_canonical_and_fixed_width)
{
    const auto empty{EmptySeed(9)};
    const auto pending{PendingSeed(9)};
    const auto ready{ReadySeed(9)};
    const auto recovery_pending{PendingSeed(
        11, 2, RosterBeaconAnchorKind::RECOVERY)};
    const auto recovery_ready{ReadySeed(
        11, 2, RosterBeaconAnchorKind::RECOVERY)};
    BOOST_REQUIRE(empty.IsStructurallyValid());
    BOOST_REQUIRE(pending.IsStructurallyValid());
    BOOST_REQUIRE(ready.IsReady());
    BOOST_CHECK(!recovery_pending.IsStructurallyValid());
    BOOST_REQUIRE(recovery_ready.IsReady());
    BOOST_CHECK(!empty.FutureBTCHeight());
    BOOST_REQUIRE(pending.FutureBTCHeight());
    BOOST_CHECK_EQUAL(*pending.FutureBTCHeight(), 800'037);
    BOOST_REQUIRE(recovery_ready.FutureBTCHeight());
    BOOST_CHECK_EQUAL(*recovery_ready.FutureBTCHeight(), 800'037);
    BOOST_CHECK(RoundTrip(empty) == empty);
    BOOST_CHECK(RoundTrip(pending) == pending);
    BOOST_CHECK(RoundTrip(ready) == ready);

    DataStream encoded;
    encoded << ready;
    BOOST_CHECK_EQUAL(encoded.size(), RosterBeaconSeed::WIRE_SIZE);
    BOOST_CHECK_EQUAL(RosterBeaconSeed::WIRE_SIZE, 112U);
    BOOST_CHECK_EQUAL(ROSTER_BEACON_FUTURE_BTC_HEIGHT_DELTA, 37U);
    BOOST_CHECK_EQUAL(ROSTER_BEACON_MAX_ANCHOR_BTC_LAG, 6U);

    auto invalid{empty};
    invalid.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = empty;
    invalid.anchor_cursor = pending.anchor_cursor;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = empty;
    invalid.anchor_btc_height = 0;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = empty;
    invalid.future_btc_hash = NonNullHash(1);
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = pending;
    invalid.future_btc_hash = NonNullHash(2);
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = pending;
    invalid.anchor_btc_height = std::numeric_limits<int32_t>::max();
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = ready;
    invalid.future_btc_hash.SetNull();
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = ready;
    invalid.future_btc_hash = invalid.anchor_cursor.btc_hash;
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = ready;
    invalid.state = static_cast<RosterBeaconState>(3);
    BOOST_CHECK(!invalid.IsStructurallyValid());

    DataStream invalid_wire;
    invalid_wire << static_cast<uint16_t>(ROSTER_BEACON_VERSION + 1)
                 << static_cast<uint8_t>(ready.anchor_kind)
                 << static_cast<uint8_t>(ready.state) << ready.epoch
                 << ready.anchor_cursor << ready.anchor_btc_height
                 << ready.future_btc_hash;
    RosterBeaconSeed decoded;
    BOOST_CHECK_THROW(invalid_wire >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(observation_and_reveal_are_exact_one_way_transitions)
{
    const auto empty{EmptySeed(9)};
    const auto pending{PendingSeed(9)};
    const auto ready{ReadySeed(9)};
    BOOST_CHECK(IsExactRosterBeaconObservation(empty, pending));
    BOOST_CHECK(!IsExactRosterBeaconObservation(empty, ready));
    BOOST_CHECK(IsExactRosterBeaconReveal(pending, ready));

    auto changed{pending};
    ++changed.epoch;
    BOOST_CHECK(!IsExactRosterBeaconObservation(empty, changed));
    changed = ready;
    changed.anchor_cursor.sys_hash = NonNullHash(100);
    BOOST_CHECK(!IsExactRosterBeaconReveal(pending, changed));
    changed = ready;
    ++changed.anchor_btc_height;
    BOOST_CHECK(!IsExactRosterBeaconReveal(pending, changed));
    BOOST_CHECK(!IsExactRosterBeaconReveal(ready, ready));
    BOOST_CHECK(!IsExactRosterBeaconReveal(empty, ready));
}

BOOST_AUTO_TEST_CASE(commitments_bind_network_state_and_complete_payload)
{
    const uint256 genesis{NonNullHash(200)};
    const auto empty{EmptySeed(9)};
    const auto pending{PendingSeed(9)};
    const auto ready{ReadySeed(9)};
    const auto ready_hash{GetRosterBeaconCommitmentHash(genesis, ready)};
    BOOST_REQUIRE(ready_hash);
    BOOST_CHECK(*ready_hash !=
                *GetRosterBeaconCommitmentHash(genesis, pending));
    BOOST_CHECK(*GetRosterBeaconCommitmentHash(genesis, empty) !=
                *GetRosterBeaconCommitmentHash(genesis, pending));
    BOOST_CHECK(*ready_hash != *GetRosterBeaconCommitmentHash(
                                   NonNullHash(201), ready));

    auto changed{ready};
    ++changed.epoch;
    BOOST_CHECK(*ready_hash !=
                *GetRosterBeaconCommitmentHash(genesis, changed));
    changed = ready;
    changed.anchor_cursor.sys_hash = NonNullHash(202);
    BOOST_CHECK(*ready_hash !=
                *GetRosterBeaconCommitmentHash(genesis, changed));
    changed = ready;
    ++changed.anchor_btc_height;
    BOOST_CHECK(*ready_hash !=
                *GetRosterBeaconCommitmentHash(genesis, changed));
    changed = ready;
    changed.future_btc_hash = NonNullHash(203);
    BOOST_CHECK(*ready_hash !=
                *GetRosterBeaconCommitmentHash(genesis, changed));
    BOOST_CHECK(!GetRosterBeaconCommitmentHash(uint256{}, ready));
}

BOOST_AUTO_TEST_CASE(modifier_requires_ready_and_binds_snapshot_beacon_network_epoch)
{
    const uint256 genesis{NonNullHash(300)};
    const uint256 snapshot_hash{NonNullHash(301)};
    const auto ready{ReadySeed(9)};
    constexpr int32_t SNAPSHOT_HEIGHT{1'152};
    const auto modifier{GetPQQuorumModifier(
        genesis, ready.epoch, SNAPSHOT_HEIGHT, snapshot_hash, ready)};
    BOOST_REQUIRE(modifier);
    BOOST_CHECK(!GetPQQuorumModifier(
        genesis, ready.epoch, SNAPSHOT_HEIGHT, snapshot_hash,
        PendingSeed(9)));
    BOOST_CHECK(!GetPQQuorumModifier(
        genesis, ready.epoch, ready.anchor_cursor.sys_height,
        snapshot_hash, ready));
    BOOST_CHECK(!GetPQQuorumModifier(
        genesis, ready.epoch + 1, SNAPSHOT_HEIGHT, snapshot_hash, ready));
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(
                                 NonNullHash(302), ready.epoch,
                                 SNAPSHOT_HEIGHT, snapshot_hash, ready));
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(
                                 genesis, ready.epoch,
                                 SNAPSHOT_HEIGHT - 1, snapshot_hash, ready));
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(
                                 genesis, ready.epoch, SNAPSHOT_HEIGHT,
                                 NonNullHash(303), ready));
    auto changed{ready};
    changed.future_btc_hash = NonNullHash(304);
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(
                                 genesis, ready.epoch, SNAPSHOT_HEIGHT,
                                 snapshot_hash, changed));
    changed = ready;
    changed.anchor_cursor.sys_hash = NonNullHash(305);
    BOOST_CHECK(*modifier == *GetPQQuorumModifier(
                                 genesis, ready.epoch, SNAPSHOT_HEIGHT,
                                 snapshot_hash, changed));
    BOOST_CHECK(*GetRosterBeaconCommitmentHash(genesis, ready) !=
                *GetRosterBeaconCommitmentHash(genesis, changed));
}

BOOST_AUTO_TEST_CASE(active_bundle_and_window_have_exact_epoch_geometry)
{
    const uint256 genesis{NonNullHash(400)};
    auto bundle{ReadyBundle(40)};
    BOOST_REQUIRE(bundle.IsStructurallyValid());
    BOOST_CHECK(bundle.IsForNewestEpoch(43));
    BOOST_CHECK(!bundle.IsForNewestEpoch(42));
    BOOST_CHECK(RoundTrip(bundle) == bundle);
    DataStream bundle_bytes;
    bundle_bytes << bundle;
    BOOST_CHECK_EQUAL(bundle_bytes.size(), ActiveRosterBeaconBundle::WIRE_SIZE);
    BOOST_CHECK_EQUAL(ActiveRosterBeaconBundle::WIRE_SIZE, 562U);

    const auto bundle_hash{GetActiveRosterBeaconBundleHash(genesis, bundle)};
    BOOST_REQUIRE(bundle_hash);
    BOOST_CHECK(*bundle_hash != *GetActiveRosterBeaconBundleHash(
                                    NonNullHash(401), bundle));
    auto changed_bundle{bundle};
    changed_bundle.seeds[0].future_btc_hash = NonNullHash(402);
    BOOST_CHECK(*bundle_hash != *GetActiveRosterBeaconBundleHash(
                                    genesis, changed_bundle));

    BOOST_CHECK(!bundle.recovery_authority_source.IsNull());
    auto incomplete_authority{bundle};
    incomplete_authority.recovery_authority_source = {};
    BOOST_CHECK(!incomplete_authority.IsStructurallyValid());

    auto invalid{bundle};
    invalid.seeds[1].state = RosterBeaconState::PENDING;
    invalid.seeds[1].future_btc_hash.SetNull();
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = bundle;
    ++invalid.seeds[2].epoch;
    BOOST_CHECK(!invalid.IsStructurallyValid());

    auto recovery{RecoveryBundle(40, 8)};
    BOOST_CHECK(recovery.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(recovery) == recovery);
    for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK(recovery.seeds[slot].anchor_cursor ==
                    recovery.seeds.front().anchor_cursor);
        BOOST_CHECK(recovery.seeds[slot].future_btc_hash ==
                    recovery.seeds.front().future_btc_hash);
    }
    const auto recovery_hash{
        GetActiveRosterBeaconBundleHash(genesis, recovery)};
    BOOST_REQUIRE(recovery_hash);
    auto changed_recovery{recovery};
    changed_recovery.recovery_authority_source =
        NormalAuthoritySource(40, 406);
    BOOST_REQUIRE(changed_recovery.IsStructurallyValid());
    BOOST_CHECK(*recovery_hash != *GetActiveRosterBeaconBundleHash(
                                      genesis, changed_recovery));

    auto window{Window(40)};
    BOOST_REQUIRE(window.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(window) == window);
    DataStream window_bytes;
    window_bytes << window;
    BOOST_CHECK_EQUAL(window_bytes.size(), RosterBeaconWindow::WIRE_SIZE);
    BOOST_CHECK_EQUAL(RosterBeaconWindow::WIRE_SIZE, 674U);
    window.next = PendingSeed(44, 9);
    BOOST_CHECK(window.IsStructurallyValid());
    window.next = ReadySeed(44, 9);
    BOOST_CHECK(window.IsStructurallyValid());
    ++window.next.epoch;
    BOOST_CHECK(!window.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(recovery_authority_source_is_exact_normal_ready_seed)
{
    const RecoveryRosterAuthoritySource empty;
    BOOST_REQUIRE(empty.IsStructurallyValid());
    BOOST_REQUIRE(empty.IsNull());
    BOOST_CHECK(RoundTrip(empty) == empty);

    const auto source{NormalAuthoritySource(40, 20)};
    BOOST_REQUIRE(source.IsStructurallyValid());
    BOOST_CHECK(!source.IsNull());
    BOOST_CHECK(RoundTrip(source) == source);
    DataStream encoded;
    encoded << source;
    BOOST_CHECK_EQUAL(encoded.size(),
                      RecoveryRosterAuthoritySource::WIRE_SIZE);
    BOOST_CHECK_EQUAL(RecoveryRosterAuthoritySource::WIRE_SIZE, 112U);

    auto invalid{source};
    invalid.normal_beacon.state = RosterBeaconState::PENDING;
    invalid.normal_beacon.future_btc_hash.SetNull();
    BOOST_CHECK(!invalid.IsStructurallyValid());
    invalid = source;
    invalid.normal_beacon.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    BOOST_CHECK(!invalid.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(recovery_window_reuses_delayed_normal_entropy_exactly)
{
    const uint256 genesis{NonNullHash(450)};
    const auto source{NormalAuthoritySource(40, 30)};
    const auto entropy{
        GetRecoveryRosterEntropyCommitment(genesis, source.normal_beacon)};
    BOOST_REQUIRE(entropy);
    BOOST_CHECK(*entropy != *GetRecoveryRosterEntropyCommitment(
                                NonNullHash(452), source.normal_beacon));
    auto changed_source{source};
    changed_source.normal_beacon.future_btc_hash = NonNullHash(453);
    BOOST_CHECK(*entropy != *GetRecoveryRosterEntropyCommitment(
                                genesis, changed_source.normal_beacon));

    const auto window{MakeRecoveryRosterBeaconWindow(
        source, /*newest_epoch=*/103)};
    BOOST_REQUIRE(window);
    BOOST_REQUIRE(IsRecoveryRosterBeaconWindow(*window));
    BOOST_CHECK(window->active.recovery_authority_source == source);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto& seed{window->active.seeds[slot]};
        BOOST_CHECK_EQUAL(seed.epoch, 100U + slot);
        BOOST_CHECK(seed.anchor_kind == RosterBeaconAnchorKind::RECOVERY);
        BOOST_CHECK(seed.anchor_cursor == source.normal_beacon.anchor_cursor);
        BOOST_CHECK_EQUAL(seed.anchor_btc_height,
                          source.normal_beacon.anchor_btc_height);
        BOOST_CHECK(seed.future_btc_hash ==
                    source.normal_beacon.future_btc_hash);
    }
    BOOST_CHECK(window->next == EmptySeed(104));

    BOOST_CHECK(!MakeRecoveryRosterBeaconWindow(
        source, /*newest_epoch=*/102));
    BOOST_CHECK(!MakeRecoveryRosterBeaconWindow(
        RecoveryRosterAuthoritySource{},
        /*newest_epoch=*/103));
}

BOOST_AUTO_TEST_CASE(newest_normal_seed_survives_mixed_recovery_windows)
{
    auto normal{Window(40)};
    BOOST_REQUIRE(FindNewestNormalReadySeed(normal));
    BOOST_CHECK(*FindNewestNormalReadySeed(normal) ==
                normal.active.seeds.back());

    normal.next = ReadySeed(44, 50);
    BOOST_REQUIRE(FindNewestNormalReadySeed(normal));
    BOOST_CHECK(*FindNewestNormalReadySeed(normal) == normal.next);

    auto mixed{RecoveryWindow(100, 51)};
    BOOST_CHECK(!FindNewestNormalReadySeed(mixed));
    mixed.active.seeds[1] = ReadySeed(101, 52);
    BOOST_REQUIRE(mixed.IsStructurallyValid());
    BOOST_REQUIRE(FindNewestNormalReadySeed(mixed));
    BOOST_CHECK(*FindNewestNormalReadySeed(mixed) == mixed.active.seeds[1]);
    BOOST_CHECK(!IsRecoveryRosterBeaconWindow(mixed));
}

BOOST_AUTO_TEST_CASE(reset_target_has_one_objective_transition)
{
    ChainLockScheduleConfig chainlock;
    chainlock.epoch_origin = 0;
    BTCCScheduleConfig btcc;
    btcc.candidate_origin = 865;
    constexpr int32_t ACTIVATION_PREDECESSOR{864};

    const auto first{NextEligibleChainLockTargetHeight(
        chainlock, ACTIVATION_PREDECESSOR)};
    BOOST_REQUIRE(first);
    BOOST_CHECK_EQUAL(*first, 865);
    const auto initialize{CanonicalRosterResetTransitionForTarget(
        chainlock, btcc, ACTIVATION_PREDECESSOR, *first)};
    BOOST_REQUIRE(initialize);
    BOOST_CHECK(*initialize ==
                RosterAuthorizationTransitionKind::INITIALIZE);

    std::optional<int32_t> later_target;
    for (const uint32_t epoch : {7U, 11U, 15U}) {
        const auto target{CanonicalRosterRecoveryTargetHeight(
            chainlock, btcc, epoch)};
        BOOST_REQUIRE(target);
        const auto recover{CanonicalRosterResetTransitionForTarget(
            chainlock, btcc, ACTIVATION_PREDECESSOR, *target)};
        BOOST_REQUIRE(recover);
        BOOST_CHECK(*recover ==
                    RosterAuthorizationTransitionKind::RECOVER);
        if (later_target) BOOST_CHECK(*target > *later_target);
        later_target = target;
    }
    BOOST_REQUIRE(later_target);

    BOOST_CHECK(!CanonicalRosterResetTransitionForTarget(
        chainlock, btcc, ACTIVATION_PREDECESSOR, *first + 5));
    BOOST_CHECK(!CanonicalRosterResetTransitionForTarget(
        chainlock, btcc, ACTIVATION_PREDECESSOR,
        *later_target + chainlock.chainlock_period));
    BOOST_CHECK(!CanonicalRosterResetTransitionForTarget(
        chainlock, btcc, ACTIVATION_PREDECESSOR, ACTIVATION_PREDECESSOR));

    auto incompatible_btcc{btcc};
    ++incompatible_btcc.candidate_origin;
    BOOST_CHECK(!CanonicalRosterResetTransitionForTarget(
        chainlock, incompatible_btcc, ACTIVATION_PREDECESSOR, *first));
}

BOOST_AUTO_TEST_CASE(recovery_mode_is_objective_from_receipted_progress)
{
    ChainLockScheduleConfig chainlock;
    chainlock.epoch_origin = 0;
    BTCCScheduleConfig btcc;
    btcc.candidate_origin = 865;

    const auto recovery_target{CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, /*epoch=*/11)};
    BOOST_REQUIRE(recovery_target);
    const auto missing_receipt{GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *recovery_target, std::nullopt)};
    BOOST_REQUIRE(missing_receipt);
    BOOST_CHECK(*missing_receipt ==
                ObjectiveRosterAuthorizationMode::PAUSE);

    const auto receipt_same_epoch{NextEligibleChainLockTargetHeight(
        chainlock, *EpochBaseHeight(chainlock, 11) - 1)};
    const auto receipt_previous_epoch{NextEligibleChainLockTargetHeight(
        chainlock, *EpochBaseHeight(chainlock, 10) - 1)};
    const auto receipt_two_epochs_behind{NextEligibleChainLockTargetHeight(
        chainlock, *EpochBaseHeight(chainlock, 9) - 1)};
    BOOST_REQUIRE(receipt_same_epoch);
    BOOST_REQUIRE(receipt_previous_epoch);
    BOOST_REQUIRE(receipt_two_epochs_behind);

    const auto same_epoch{GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *recovery_target, *receipt_same_epoch)};
    const auto previous_epoch{GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *recovery_target, *receipt_previous_epoch)};
    const auto stale{GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *recovery_target,
        *receipt_two_epochs_behind)};
    BOOST_REQUIRE(same_epoch);
    BOOST_REQUIRE(previous_epoch);
    BOOST_REQUIRE(stale);
    BOOST_CHECK(*same_epoch == ObjectiveRosterAuthorizationMode::NORMAL);
    BOOST_CHECK(*previous_epoch ==
                ObjectiveRosterAuthorizationMode::NORMAL);
    BOOST_CHECK(*stale == ObjectiveRosterAuthorizationMode::RECOVER);

    const auto ordinary_target{NextEligibleChainLockTargetHeight(
        chainlock, *recovery_target)};
    BOOST_REQUIRE(ordinary_target);
    const auto ordinary{GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *ordinary_target,
        *receipt_two_epochs_behind)};
    BOOST_REQUIRE(ordinary);
    BOOST_CHECK(*ordinary == ObjectiveRosterAuthorizationMode::PAUSE);
}

BOOST_AUTO_TEST_CASE(recovery_mode_rejects_invalid_geometry)
{
    ChainLockScheduleConfig chainlock;
    chainlock.epoch_origin = 0;
    BTCCScheduleConfig btcc;
    btcc.candidate_origin = 865;

    const auto target{CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, /*epoch=*/11)};
    BOOST_REQUIRE(target);
    const auto old_receipt{NextEligibleChainLockTargetHeight(
        chainlock, *EpochBaseHeight(chainlock, 9) - 1)};
    BOOST_REQUIRE(old_receipt);

    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 10, *target, *old_receipt));
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *target + 1, *old_receipt));
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *target, *old_receipt + 1));
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *target, *target));
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, 11, *target, *target + chainlock.chainlock_period));

    auto invalid_chainlock{chainlock};
    ++invalid_chainlock.epoch_blocks;
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        invalid_chainlock, btcc, 11, *target, *old_receipt));
    auto invalid_btcc{btcc};
    ++invalid_btcc.candidate_period;
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, invalid_btcc, 11, *target, *old_receipt));

    BOOST_CHECK(!CanonicalRosterRecoveryTargetHeight(
        chainlock, btcc, std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(!GetObjectiveRosterAuthorizationMode(
        chainlock, btcc, std::numeric_limits<uint32_t>::max(),
        std::numeric_limits<int32_t>::max(), *old_receipt));
}

BOOST_AUTO_TEST_CASE(initialization_and_recovery_bind_the_complete_window)
{
    const uint256 genesis{NonNullHash(500)};
    const auto initial_window{InitialNormalWindow(0)};
    BOOST_REQUIRE(IsInitialNormalRosterBeaconWindow(initial_window));
    BOOST_CHECK(!IsRecoveryRosterBeaconWindow(initial_window));
    const auto initialize{Transition(
        RosterAuthorizationTransitionKind::INITIALIZE, initial_window)};
    BOOST_REQUIRE(initialize.IsStructurallyValid());
    const auto initial_state{
        GetRosterAuthorizationStateHash(genesis, initialize)};
    BOOST_REQUIRE(initial_state);

    auto invalid_initialize{initialize};
    invalid_initialize.previous = Prior(initial_window);
    BOOST_CHECK(!invalid_initialize.IsStructurallyValid());

    auto recovered_window{RecoveryWindow(
        initial_window.active.recovery_authority_source,
        100)};
    const auto recovery{Transition(
        RosterAuthorizationTransitionKind::RECOVER, recovered_window,
        Prior(initial_window))};
    BOOST_REQUIRE(recovery.IsStructurallyValid());
    BOOST_CHECK(recovery.new_window.active.recovery_authority_source ==
                initial_window.active.recovery_authority_source);
    const auto pruned_state{
        GetRosterAuthorizationStateHash(genesis, recovery)};
    BOOST_REQUIRE(pruned_state);

    auto recovery_without_prior{recovery};
    recovery_without_prior.previous.reset();
    BOOST_CHECK(!recovery_without_prior.IsStructurallyValid());
    BOOST_CHECK(!GetRosterAuthorizationStateHash(
        genesis, recovery_without_prior));

    auto recovery_without_base{recovery};
    recovery_without_base.authorization_base = {};
    BOOST_CHECK(!recovery_without_base.IsStructurallyValid());

    auto repeated_recovery_window{RecoveryWindow(
        recovered_window.active.recovery_authority_source,
        104)};
    const auto repeated_recovery{Transition(
        RosterAuthorizationTransitionKind::RECOVER,
        repeated_recovery_window, Prior(recovered_window))};
    BOOST_REQUIRE(repeated_recovery.IsStructurallyValid());
    BOOST_CHECK(repeated_recovery.new_window.active
                    .recovery_authority_source ==
                recovered_window.active.recovery_authority_source);
    BOOST_CHECK(*pruned_state !=
                *GetRosterAuthorizationStateHash(
                    genesis, repeated_recovery));

    recovered_window.next = PendingSeed(104, 21);
    auto pending_recovery{Transition(
        RosterAuthorizationTransitionKind::RECOVER, recovered_window,
        Prior(initial_window))};
    BOOST_CHECK(!pending_recovery.IsStructurallyValid());

    auto noncanonical_initial{Transition(
        RosterAuthorizationTransitionKind::INITIALIZE, Window(0))};
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(
        noncanonical_initial.new_window));
    BOOST_CHECK(!noncanonical_initial.IsStructurallyValid());
    auto recovery_initial{Transition(
        RosterAuthorizationTransitionKind::INITIALIZE,
        RecoveryWindow(0))};
    BOOST_CHECK(!recovery_initial.IsStructurallyValid());

    auto changed_initial{initial_window};
    changed_initial.active.seeds[1].anchor_cursor.sys_hash =
        NonNullHash(500'003);
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = initial_window;
    ++changed_initial.active.seeds[1].anchor_btc_height;
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = initial_window;
    changed_initial.active.seeds[1].future_btc_hash =
        NonNullHash(500'004);
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = initial_window;
    changed_initial.active.seeds[1].anchor_kind =
        RosterBeaconAnchorKind::RECOVERY;
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = initial_window;
    changed_initial.next = PendingSeed(4, 50);
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = InitialNormalWindow(1);
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));
    changed_initial = initial_window;
    changed_initial.active.recovery_authority_source =
        NormalAuthoritySource(0, 51);
    BOOST_CHECK(!IsInitialNormalRosterBeaconWindow(changed_initial));

    auto misaligned_window{RecoveryWindow(0)};
    for (auto& seed : misaligned_window.active.seeds) ++seed.epoch;
    ++misaligned_window.next.epoch;
    BOOST_REQUIRE(misaligned_window.IsStructurallyValid());
    auto misaligned{Transition(RosterAuthorizationTransitionKind::RECOVER,
                               misaligned_window, Prior(initial_window))};
    BOOST_CHECK(!misaligned.IsStructurallyValid());
    auto mixed{RecoveryWindow(100, 20)};
    mixed.active.seeds[2] = ReadySeed(102, 22);
    BOOST_CHECK(!IsRecoveryRosterBeaconWindow(mixed));
}

BOOST_AUTO_TEST_CASE(normal_state_machine_forbids_reveal_replacement_and_revert)
{
    const uint256 genesis{NonNullHash(600)};
    const auto empty_window{Window(40)};
    auto keep{Transition(RosterAuthorizationTransitionKind::KEEP,
                         empty_window, Prior(empty_window))};
    BOOST_CHECK(keep.IsStructurallyValid());

    auto pending_window{empty_window};
    pending_window.next = PendingSeed(44, 30);
    auto observe{Transition(RosterAuthorizationTransitionKind::OBSERVE,
                            pending_window, Prior(empty_window))};
    BOOST_REQUIRE(observe.IsStructurallyValid());
    const auto observed_state{
        GetRosterAuthorizationStateHash(genesis, observe)};
    BOOST_REQUIRE(observed_state);

    auto replaced{pending_window};
    replaced.next = PendingSeed(44, 31);
    auto bad_observe{Transition(RosterAuthorizationTransitionKind::OBSERVE,
                                replaced, Prior(pending_window))};
    BOOST_CHECK(!bad_observe.IsStructurallyValid());

    auto ready_window{pending_window};
    ready_window.next = ReadySeed(44, 30);
    auto reveal{Transition(
        RosterAuthorizationTransitionKind::REVEAL, ready_window,
        RosterAuthorizationPriorState{*observed_state, pending_window})};
    BOOST_REQUIRE(reveal.IsStructurallyValid());

    auto direct_reveal{Transition(RosterAuthorizationTransitionKind::REVEAL,
                                  ready_window, Prior(empty_window))};
    BOOST_CHECK(!direct_reveal.IsStructurallyValid());
    auto changed_ready{ready_window};
    changed_ready.next.future_btc_hash = NonNullHash(601);
    auto rewrite{Transition(RosterAuthorizationTransitionKind::KEEP,
                            changed_ready, Prior(ready_window))};
    BOOST_CHECK(!rewrite.IsStructurallyValid());
    auto revert{Transition(RosterAuthorizationTransitionKind::KEEP,
                           pending_window, Prior(ready_window))};
    BOOST_CHECK(!revert.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(rotation_consumes_ready_and_shifts_exactly_one_slot)
{
    auto old_window{Window(40)};
    old_window.next = ReadySeed(44, 40);
    BOOST_REQUIRE(old_window.IsStructurallyValid());

    RosterBeaconWindow new_window;
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        new_window.active.seeds[slot] =
            old_window.active.seeds[slot + 1];
    }
    new_window.active.seeds.back() = old_window.next;
    new_window.active.recovery_authority_source.normal_beacon =
        old_window.next;
    new_window.next = EmptySeed(45);
    BOOST_REQUIRE(IsExactRosterBeaconRotation(old_window, new_window));
    auto rotate{Transition(RosterAuthorizationTransitionKind::ROTATE,
                           new_window, Prior(old_window))};
    BOOST_CHECK(rotate.IsStructurallyValid());

    auto pending_next{new_window};
    pending_next.next = PendingSeed(45, 41);
    BOOST_CHECK(IsExactRosterBeaconRotation(old_window, pending_next));

    auto invalid{new_window};
    invalid.active.seeds[0] = ReadySeed(41, 99);
    BOOST_CHECK(!IsExactRosterBeaconRotation(old_window, invalid));
    invalid = new_window;
    invalid.active.seeds.back() = ReadySeed(44, 99);
    BOOST_CHECK(!IsExactRosterBeaconRotation(old_window, invalid));
    invalid = new_window;
    invalid.next = ReadySeed(45, 41);
    BOOST_CHECK(!IsExactRosterBeaconRotation(old_window, invalid));
}

BOOST_AUTO_TEST_CASE(normal_observation_binds_advance_cutoff_and_hard_anchor)
{
    const uint256 genesis{NonNullHash(800)};
    const auto previous_window{Window(40)};

    auto before_cutoff{NormalInput(previous_window, 43)};
    SetAcceptedAdvance(before_cutoff);
    before_cutoff.accepted_anchor.reset();
    const auto keep{
        DeriveNormalRosterAuthorizationDecision(genesis, before_cutoff)};
    BOOST_REQUIRE(keep);
    BOOST_CHECK(keep->transition.kind ==
                RosterAuthorizationTransitionKind::KEEP);
    BOOST_CHECK(keep->transition.new_window == previous_window);
    BOOST_CHECK_EQUAL(keep->authorization_mask, 0b1111);

    auto observe{before_cutoff};
    CoverNextSnapshot(observe);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, observe));
    SetAcceptedAdvance(observe);
    const auto decision{
        DeriveNormalRosterAuthorizationDecision(genesis, observe)};
    BOOST_REQUIRE(decision);
    BOOST_CHECK(decision->transition.kind ==
                RosterAuthorizationTransitionKind::OBSERVE);
    BOOST_CHECK(decision->transition.new_window.active ==
                previous_window.active);
    BOOST_CHECK(decision->transition.new_window.next.state ==
                RosterBeaconState::PENDING);
    BOOST_CHECK(decision->transition.new_window.next.anchor_cursor ==
                observe.accepted_btcc_cursor);
    BOOST_CHECK_EQUAL(
        decision->transition.new_window.next.anchor_btc_height, 900'000);
    const auto accepted_mask{ValidateNormalRosterAuthorizationDecision(
        genesis, observe, decision->transition, decision->state_hash)};
    BOOST_REQUIRE(accepted_mask);
    BOOST_CHECK_EQUAL(*accepted_mask, 0b1111);

    auto lagged{observe};
    lagged.accepted_anchor->active_tip_height =
        lagged.accepted_anchor->btc_height + 7;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, lagged));
    auto inactive{observe};
    inactive.accepted_anchor->is_active = false;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, inactive));
    auto wrong_anchor{observe};
    wrong_anchor.accepted_anchor->cursor.btc_hash = NonNullHash(801);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          wrong_anchor));

    auto wrong_cursor{observe};
    --wrong_cursor.accepted_btcc_cursor.sys_height;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          wrong_cursor));
    auto false_coverage{observe};
    false_coverage.next_snapshot.prior_authorization_is_descendant = false;
    false_coverage.next_snapshot.hash.SetNull();
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          false_coverage));
    auto wrong_cutoff_hash{observe};
    wrong_cutoff_hash.next_snapshot.hash = NonNullHash(804);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          wrong_cutoff_hash));
    auto early_claim{before_cutoff};
    early_claim.next_snapshot.prior_authorization_is_descendant = true;
    early_claim.next_snapshot.hash = NonNullHash(802);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          early_claim));

    auto missed_round{before_cutoff};
    missed_round.authorization_base.height = 2'995;
    missed_round.authorization_base.block_hash =
        missed_round.previous_btcc_cursor.sys_hash;
    missed_round.previous_btcc_cursor = BTCCursor{
        2'998, NonNullHash(80'005), NonNullHash(80'006)};
    missed_round.next_snapshot.height = 2'998;
    missed_round.next_snapshot.hash.SetNull();
    missed_round.next_snapshot.prior_authorization_is_descendant = false;
    const auto missed_keep{
        DeriveNormalRosterAuthorizationDecision(genesis, missed_round)};
    BOOST_REQUIRE(missed_keep);
    BOOST_CHECK(missed_keep->transition.kind ==
                RosterAuthorizationTransitionKind::KEEP);
    auto false_observe_facts{missed_round};
    false_observe_facts.accepted_anchor = observe.accepted_anchor;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, false_observe_facts));

    auto claimed{decision->transition};
    claimed.target_block_hash = NonNullHash(803);
    const auto self_consistent_wrong_hash{
        GetRosterAuthorizationStateHash(genesis, claimed)};
    BOOST_REQUIRE(self_consistent_wrong_hash);
    BOOST_CHECK(!ValidateNormalRosterAuthorizationDecision(
        genesis, observe, claimed, *self_consistent_wrong_hash));
}

BOOST_AUTO_TEST_CASE(normal_reveal_requires_exact_active_h37_and_six_confirmations)
{
    const uint256 genesis{NonNullHash(900)};
    auto pending_window{Window(40)};
    pending_window.next = PendingSeed(44, 90);
    auto input{NormalInput(pending_window, 43)};
    input.pending_reveal = RevealRange(pending_window.next);
    auto revealed_source{pending_window.next};
    revealed_source.state = RosterBeaconState::READY;
    revealed_source.future_btc_hash = input.pending_reveal->future_hash;
    input.recovery_authority_source.normal_beacon = revealed_source;

    const auto decision{
        DeriveNormalRosterAuthorizationDecision(genesis, input)};
    BOOST_REQUIRE(decision);
    BOOST_CHECK(decision->transition.kind ==
                RosterAuthorizationTransitionKind::REVEAL);
    BOOST_CHECK(decision->transition.new_window.next.IsReady());
    BOOST_CHECK(decision->transition.new_window.next.future_btc_hash ==
                input.pending_reveal->future_hash);
    BOOST_CHECK(decision->transition.new_window.active
                    .recovery_authority_source.normal_beacon ==
                decision->transition.new_window.next);
    BOOST_CHECK_EQUAL(decision->authorization_mask, 0b1111);

    auto stale_source{input};
    stale_source.recovery_authority_source =
        pending_window.active.recovery_authority_source;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, stale_source));

    auto five_confirmations{input};
    five_confirmations.pending_reveal =
        RevealRange(pending_window.next, 5);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, five_confirmations));
    auto h36{input};
    --h36.pending_reveal->future_height;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, h36));
    auto h38{input};
    ++h38.pending_reveal->future_height;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, h38));
    auto wrong_anchor{input};
    wrong_anchor.pending_reveal->anchor_hash = NonNullHash(901);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          wrong_anchor));
    auto inactive{input};
    inactive.pending_reveal->is_active = false;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, inactive));

    auto claimed{decision->transition};
    claimed.new_window.next.future_btc_hash = NonNullHash(902);
    const auto forged_shape_hash{
        GetRosterAuthorizationStateHash(genesis, claimed)};
    BOOST_REQUIRE(forged_shape_hash);
    BOOST_CHECK(!ValidateNormalRosterAuthorizationDecision(
        genesis, input, claimed, *forged_shape_hash));
}

BOOST_AUTO_TEST_CASE(normal_rotation_consumes_ready_and_may_observe_fresh_next)
{
    const uint256 genesis{NonNullHash(1'000)};
    auto ready_window{Window(40)};
    ready_window.next = ReadySeed(44, 100);
    auto input{NormalInput(ready_window, 44)};
    input.ready_rotation = RevealRange(ready_window.next);

    const auto decision{
        DeriveNormalRosterAuthorizationDecision(genesis, input)};
    BOOST_REQUIRE(decision);
    BOOST_CHECK(decision->transition.kind ==
                RosterAuthorizationTransitionKind::ROTATE);
    BOOST_CHECK_EQUAL(decision->authorization_mask, 0b0111);
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK(decision->transition.new_window.active.seeds[slot] ==
                    ready_window.active.seeds[slot + 1]);
    }
    BOOST_CHECK(decision->transition.new_window.active.seeds.back() ==
                ready_window.next);
    BOOST_CHECK(decision->transition.new_window.next == EmptySeed(45));
    BOOST_CHECK(decision->transition.new_window.active
                    .recovery_authority_source.normal_beacon ==
                ready_window.next);

    auto stale_authority{input};
    stale_authority.recovery_authority_source =
        ready_window.active.recovery_authority_source;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, stale_authority));

    auto missing_ready_range{input};
    missing_ready_range.ready_rotation.reset();
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, missing_ready_range));
    auto reorged_ready{input};
    reorged_ready.ready_rotation->is_active = false;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          reorged_ready));
    auto wrong_ready_hash{input};
    wrong_ready_hash.ready_rotation->future_hash = NonNullHash(1'002);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, wrong_ready_hash));
    auto insufficient_ready{input};
    insufficient_ready.ready_rotation = RevealRange(ready_window.next, 5);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, insufficient_ready));

    auto observe_after_rotation{input};
    CoverNextSnapshot(observe_after_rotation);
    SetAcceptedAdvance(observe_after_rotation, 910'000, 6);
    const auto observed{DeriveNormalRosterAuthorizationDecision(
        genesis, observe_after_rotation)};
    BOOST_REQUIRE(observed);
    BOOST_CHECK(observed->transition.kind ==
                RosterAuthorizationTransitionKind::ROTATE);
    BOOST_CHECK(observed->transition.new_window.next.state ==
                RosterBeaconState::PENDING);
    BOOST_CHECK(observed->transition.new_window.next.anchor_cursor ==
                observe_after_rotation.accepted_btcc_cursor);

    auto missing_anchor{observe_after_rotation};
    missing_anchor.accepted_anchor.reset();
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          missing_anchor));
    auto extraneous_reveal{input};
    extraneous_reveal.pending_reveal = RevealRange(PendingSeed(44, 100));
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          extraneous_reveal));

    auto changed{decision->transition};
    changed.new_window.active.seeds[0] = ReadySeed(41, 1'001);
    BOOST_CHECK(!ValidateNormalRosterAuthorizationDecision(
        genesis, input, changed, decision->state_hash));
}

BOOST_AUTO_TEST_CASE(normal_rotation_can_atomically_reveal_pending_seed)
{
    const uint256 genesis{NonNullHash(1'100)};
    auto pending_window{Window(40)};
    pending_window.next = PendingSeed(44, 110);
    auto input{NormalInput(pending_window, 44)};
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis, input));

    input.pending_reveal = RevealRange(pending_window.next);
    auto revealed_source{pending_window.next};
    revealed_source.state = RosterBeaconState::READY;
    revealed_source.future_btc_hash = input.pending_reveal->future_hash;
    input.recovery_authority_source.normal_beacon = revealed_source;
    const auto decision{
        DeriveNormalRosterAuthorizationDecision(genesis, input)};
    BOOST_REQUIRE(decision);
    BOOST_CHECK(decision->transition.kind ==
                RosterAuthorizationTransitionKind::ROTATE);
    BOOST_CHECK(IsExactRosterBeaconReveal(
        pending_window.next,
        decision->transition.new_window.active.seeds.back()));
    BOOST_CHECK(IsExactRosterBeaconRotation(
        pending_window, decision->transition.new_window));
    BOOST_CHECK(decision->transition.IsStructurallyValid());

    auto insufficient{input};
    insufficient.pending_reveal = RevealRange(pending_window.next, 5);
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          insufficient));

    auto observe_fresh{input};
    CoverNextSnapshot(observe_fresh);
    SetAcceptedAdvance(observe_fresh, 920'000, 0);
    const auto combined{DeriveNormalRosterAuthorizationDecision(
        genesis, observe_fresh)};
    BOOST_REQUIRE(combined);
    BOOST_CHECK(combined->transition.new_window.next.state ==
                RosterBeaconState::PENDING);

    auto skipped_epoch{input};
    skipped_epoch.newest_epoch = 45;
    skipped_epoch.next_snapshot.epoch = 46;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(genesis,
                                                          skipped_epoch));
}

BOOST_AUTO_TEST_CASE(normal_transitions_carry_recovery_authority_until_drained)
{
    const uint256 genesis{NonNullHash(1'150)};
    auto window{RecoveryWindow(100, 115)};
    const auto original_source{
        window.active.recovery_authority_source};
    std::optional<NormalRosterAuthorizationInput> final_drain_input;
    std::optional<NormalRosterAuthorizationDecision> final_drain_decision;

    for (uint32_t newest_epoch{104}; newest_epoch <= 107;
         ++newest_epoch) {
        window.next = ReadySeed(newest_epoch, newest_epoch);
        auto input{NormalInput(window, newest_epoch)};
        input.ready_rotation = RevealRange(window.next);
        if (newest_epoch == 107) {
            // The rotation that removes the final recovery roster also
            // commits the already-authenticated normal seed it consumes.
            input.recovery_authority_source.normal_beacon = window.next;
        }
        if (newest_epoch == 104) {
            auto changed_source{input};
            changed_source.recovery_authority_source =
                NormalAuthoritySource(/*source_epoch=*/43, 1'151);
            BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
                genesis, changed_source));

        }
        const auto decision{
            DeriveNormalRosterAuthorizationDecision(genesis, input)};
        BOOST_REQUIRE(decision);
        const auto verified{ValidateNormalRosterAuthorizationDecision(
            genesis, input, decision->transition, decision->state_hash)};
        BOOST_REQUIRE(verified);
        BOOST_CHECK(decision->transition.kind ==
                    RosterAuthorizationTransitionKind::ROTATE);
        const auto& expected_source{newest_epoch == 107
            ? input.recovery_authority_source
            : original_source};
        BOOST_CHECK(decision->transition.new_window.active
                        .recovery_authority_source == expected_source);
        if (newest_epoch == 107) {
            final_drain_input = input;
            final_drain_decision = *decision;
        }
        window = decision->transition.new_window;
    }

    BOOST_CHECK(!HasRecoveryRosterBeacon(window));
    BOOST_CHECK(window.active.recovery_authority_source.normal_beacon ==
                window.active.seeds.back());
    auto refresh{NormalInput(window, /*newest_epoch=*/107)};
    const auto refreshed{
        DeriveNormalRosterAuthorizationDecision(genesis, refresh)};
    BOOST_REQUIRE(refreshed);
    BOOST_CHECK(refreshed->transition.kind ==
                RosterAuthorizationTransitionKind::KEEP);
    BOOST_CHECK(refreshed->transition.new_window.active
                    .recovery_authority_source.normal_beacon ==
                window.active.seeds.back());
    BOOST_CHECK(refreshed->transition.new_window.active
                    .recovery_authority_source ==
                window.active.recovery_authority_source);

    const auto recovered{MakeRecoveryRosterBeaconWindow(
        window.active.recovery_authority_source,
        /*newest_epoch=*/111)};
    BOOST_REQUIRE(recovered);
    const auto recovery{Transition(
        RosterAuthorizationTransitionKind::RECOVER, *recovered,
        Prior(window))};
    BOOST_REQUIRE(recovery.IsStructurallyValid());
    BOOST_CHECK(GetRosterAuthorizationStateHash(genesis, recovery));

    auto stale_after_drain{refresh};
    stale_after_drain.recovery_authority_source = original_source;
    BOOST_CHECK(!DeriveNormalRosterAuthorizationDecision(
        genesis, stale_after_drain));
    BOOST_REQUIRE(final_drain_input);
    BOOST_REQUIRE(final_drain_decision);
    final_drain_input->recovery_authority_source = original_source;
    BOOST_CHECK(!ValidateNormalRosterAuthorizationDecision(
        genesis, *final_drain_input,
        final_drain_decision->transition,
        final_drain_decision->state_hash));
}

BOOST_AUTO_TEST_CASE(normal_masks_exclude_explicit_bootstrap_and_recovery)
{
    BOOST_REQUIRE(GetNormalRosterAuthorizationMask(
        RosterAuthorizationTransitionKind::KEEP));
    BOOST_CHECK_EQUAL(*GetNormalRosterAuthorizationMask(
                          RosterAuthorizationTransitionKind::KEEP),
                      0b1111);
    BOOST_CHECK_EQUAL(*GetNormalRosterAuthorizationMask(
                          RosterAuthorizationTransitionKind::OBSERVE),
                      0b1111);
    BOOST_CHECK_EQUAL(*GetNormalRosterAuthorizationMask(
                          RosterAuthorizationTransitionKind::REVEAL),
                      0b1111);
    BOOST_CHECK_EQUAL(*GetNormalRosterAuthorizationMask(
                          RosterAuthorizationTransitionKind::ROTATE),
                      0b0111);
    BOOST_CHECK(!GetNormalRosterAuthorizationMask(
        RosterAuthorizationTransitionKind::INITIALIZE));
    BOOST_CHECK(!GetNormalRosterAuthorizationMask(
        RosterAuthorizationTransitionKind::RECOVER));
    BOOST_CHECK(!GetNormalRosterAuthorizationMask(
        static_cast<RosterAuthorizationTransitionKind>(255)));
}

BOOST_AUTO_TEST_SUITE_END()
