// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <ostream>
#include <set>
#include <span>
#include <vector>

using namespace llmq::pq;

namespace llmq::pq {

std::ostream& operator<<(std::ostream& out, QuorumBuildError value)
{
    return out << static_cast<unsigned>(value);
}

} // namespace llmq::pq

namespace {

uint256 NonNullHash(uint64_t value, uint64_t salt = 0)
{
    uint256 hash;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        hash.begin()[i] = static_cast<uint8_t>(value >> (8 * i));
        hash.begin()[8 + i] = static_cast<uint8_t>(salt >> (8 * i));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

CKeyID KeyId(uint64_t value)
{
    CKeyID key;
    for (std::size_t i{0}; i < sizeof(value); ++i) {
        key.begin()[i] = static_cast<uint8_t>(value >> (8 * i));
    }
    key.begin()[key.size() - 1] = 0xa5;
    return key;
}

CDeterministicMNCPtr Member(uint32_t tag,
                            bool banned = false,
                            bool confirmed = true,
                            uint256 cached_score_seed = uint256{})
{
    auto dmn = std::make_shared<CDeterministicMN>(tag + 1);
    dmn->proTxHash = NonNullHash(10'000 + tag);
    dmn->collateralOutpoint = COutPoint(NonNullHash(20'000 + tag), tag + 1);

    auto state = std::make_shared<CDeterministicMNState>();
    state->keyIDOwner = KeyId(30'000 + tag);
    state->nRegisteredHeight = 100;
    if (confirmed) {
        state->UpdateConfirmedHash(dmn->proTxHash, NonNullHash(40'000 + tag));
        if (!cached_score_seed.IsNull()) {
            state->confirmedHashWithProRegTxHash = cached_score_seed;
        }
    }
    if (banned) state->BanIfNotBanned(200);
    dmn->pdmnState = std::move(state);
    return dmn;
}

CDeterministicMNList Snapshot(int32_t height,
                              const uint256& block_hash,
                              std::size_t count,
                              bool reverse = false,
                              bool tie_first_two = false,
                              bool add_banned_and_unconfirmed = false)
{
    CDeterministicMNList snapshot(block_hash, height,
                                  static_cast<uint32_t>(count));
    std::vector<CDeterministicMNCPtr> members;
    members.reserve(count + (add_banned_and_unconfirmed ? 2 : 0));
    const uint256 tied_seed{tie_first_two ? NonNullHash(0xdeadbeef) : uint256{}};
    for (std::size_t i{0}; i < count; ++i) {
        members.push_back(Member(static_cast<uint32_t>(i), false, true,
                                 i < 2 ? tied_seed : uint256{}));
    }
    if (add_banned_and_unconfirmed) {
        members.push_back(Member(static_cast<uint32_t>(count), true));
        members.push_back(Member(static_cast<uint32_t>(count + 1), false, false));
    }
    if (reverse) std::reverse(members.begin(), members.end());
    for (const auto& member : members) {
        snapshot.AddMN(member, /*fBumpTotalCount=*/false);
    }
    return snapshot;
}

ChainLockScheduleConfig Schedule()
{
    ChainLockScheduleConfig schedule;
    schedule.epoch_origin = 1440;
    return schedule;
}

QuorumBuildConfig BuildConfig(uint32_t snapshot_lag = 144)
{
    QuorumBuildConfig config;
    config.schedule = Schedule();
    config.roster_snapshot_lag_blocks = snapshot_lag;
    config.registration_cutoff_blocks = snapshot_lag;
    config.future_horizon_epochs = 8;
    return config;
}

OperatorKeyState KeyState(const ChainLockScheduleConfig& schedule,
                          const uint256& pro_tx_hash,
                          uint32_t epoch,
                          int32_t snapshot_height,
                          uint32_t key_tag,
                          bool include_child = true)
{
    const auto view = DeriveOperatorKeyScheduleView(
        schedule, snapshot_height, /*registration_cutoff_blocks=*/144,
        /*future_horizon_epochs=*/8);
    BOOST_REQUIRE(view);

    OperatorKeyState state = OperatorKeyState::ForOperator(pro_tx_hash);
    state.has_global_key = 1;
    state.global_key_active = 1;
    state.global_key.key_version = 1;
    state.global_key.public_key[0] =
        static_cast<uint8_t>((key_tag & 0x7fU) | 0x80U);
    state.global_key.activated_height = 1;
    state.global_key.child_key_commitment.generation = 1;
    state.global_key.child_key_commitment.first_epoch = epoch;
    state.global_key.child_key_commitment.tree_id =
        NonNullHash(50'000 + key_tag);
    state.global_key.child_key_commitment.root =
        NonNullHash(60'000 + key_tag);
    state.schedule_initialized = 1;
    state.schedule = OperatorKeyScheduleState::FromView(*view);
    if (include_child) {
        state.frozen_child_roots.push_back(FrozenChildRootRecord{
            pro_tx_hash,
            1,
            epoch,
            state.global_key.child_key_commitment,
        });
    }
    BOOST_REQUIRE(state.IsStructurallyValid());
    return state;
}

std::vector<OperatorKeyState> KeyStates(uint32_t count,
                                        uint32_t epoch,
                                        int32_t snapshot_height)
{
    std::vector<OperatorKeyState> states;
    states.reserve(count);
    for (uint32_t member{0}; member < count; ++member) {
        states.push_back(KeyState(
            Schedule(), NonNullHash(10'000 + member), epoch,
            snapshot_height, member + 1));
    }
    return states;
}

std::size_t FindMember(const FrozenQuorumRoster& roster, const uint256& pro_tx_hash)
{
    const auto it = std::find_if(
        roster.members.begin(), roster.members.end(),
        [&](const FrozenQuorumMember& member) {
            return member.pro_tx_hash == pro_tx_hash;
        });
    return static_cast<std::size_t>(std::distance(roster.members.begin(), it));
}

bool IsBitSet(const QuorumBitmap& bitmap, std::size_t slot)
{
    return (bitmap[slot / 8] &
            static_cast<uint8_t>(uint8_t{1} << (slot % 8))) != 0;
}

bool ContainsMember(const FrozenQuorumRoster& roster,
                    const uint256& pro_tx_hash)
{
    return FindMember(roster, pro_tx_hash) != QUORUM_SIZE;
}

struct IndexChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;

    IndexChain(int32_t tip_height, int32_t fork_height, uint64_t fork_salt)
        : hashes(static_cast<std::size_t>(tip_height) + 1),
          indices(static_cast<std::size_t>(tip_height) + 1)
    {
        for (int32_t height{0}; height <= tip_height; ++height) {
            const uint64_t salt{height >= fork_height ? fork_salt : 0};
            hashes[height] = NonNullHash(static_cast<uint64_t>(height) + 1, salt);
            indices[height].nHeight = height;
            indices[height].phashBlock = &hashes[height];
            indices[height].pprev = height == 0 ? nullptr : &indices[height - 1];
            indices[height].BuildSkip();
        }
    }

    const CBlockIndex& At(int32_t height) const
    {
        return indices.at(static_cast<std::size_t>(height));
    }

    const CBlockIndex& Tip() const { return indices.back(); }
};

} // namespace

BOOST_AUTO_TEST_SUITE(pq_quorum_builder_tests)

BOOST_AUTO_TEST_CASE(modifier_binds_network_epoch_and_base)
{
    const uint256 genesis{NonNullHash(1)};
    const uint256 base{NonNullHash(2)};
    const auto modifier{GetPQQuorumModifier(genesis, 4, base)};
    BOOST_REQUIRE(modifier);
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(NonNullHash(3), 4, base));
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(genesis, 5, base));
    BOOST_CHECK(*modifier != *GetPQQuorumModifier(genesis, 4, NonNullHash(4)));
    BOOST_CHECK(!GetPQQuorumModifier(uint256{}, 4, base));
    BOOST_CHECK(!GetPQQuorumModifier(genesis, 4, uint256{}));
}

BOOST_AUTO_TEST_CASE(order_is_insertion_independent_and_ties_match_legacy_order)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    const uint256 genesis{NonNullHash(5)};
    const uint256 base_hash{NonNullHash(6)};
    const uint256 snapshot_hash{NonNullHash(7)};
    const auto forward = Snapshot(SNAPSHOT_HEIGHT, snapshot_hash, QUORUM_SIZE,
                                  false, true);
    const auto reverse = Snapshot(SNAPSHOT_HEIGHT, snapshot_hash, QUORUM_SIZE,
                                  true, true);

    const auto a = BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, forward, {}, {});
    const auto b = BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, reverse, {}, {});
    BOOST_REQUIRE(a);
    BOOST_REQUIRE(b);
    BOOST_CHECK(a->descriptor == b->descriptor);
    for (std::size_t i{0}; i < QUORUM_SIZE; ++i) {
        BOOST_CHECK(a->members[i].pro_tx_hash == b->members[i].pro_tx_hash);
    }

    // The first two members have identical cached score inputs. The legacy
    // reverse-iterator comparator orders the larger collateral outpoint first.
    BOOST_CHECK_LT(FindMember(*a, NonNullHash(10'001)),
                   FindMember(*a, NonNullHash(10'000)));
}

BOOST_AUTO_TEST_CASE(eligibility_keys_and_roots_are_derived_not_fabricated)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    const uint256 genesis{NonNullHash(8)};
    const auto snapshot = Snapshot(SNAPSHOT_HEIGHT, NonNullHash(9), QUORUM_SIZE,
                                   false, false,
                                   /*add_banned_and_unconfirmed=*/true);
    const uint256 banned_hash{NonNullHash(10'000 + QUORUM_SIZE)};
    const uint256 unconfirmed_hash{NonNullHash(10'001 + QUORUM_SIZE)};

    const auto without_keys = BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(10), snapshot, {}, {});
    BOOST_REQUIRE(without_keys);
    BOOST_CHECK_EQUAL(without_keys->descriptor.valid_count, 0U);
    BOOST_CHECK_EQUAL(FindMember(*without_keys, banned_hash), QUORUM_SIZE);
    BOOST_CHECK_EQUAL(FindMember(*without_keys, unconfirmed_hash), QUORUM_SIZE);

    const uint256 keyed_hash{without_keys->members[0].pro_tx_hash};
    const uint256 absent_hash{without_keys->members[1].pro_tx_hash};
    std::vector<OperatorKeyState> states;
    states.push_back(KeyState(Schedule(), keyed_hash, EPOCH, SNAPSHOT_HEIGHT, 1));
    states.push_back(KeyState(Schedule(), absent_hash, EPOCH, SNAPSHOT_HEIGHT, 2,
                              /*include_child=*/false));
    // State belonging to an ineligible/banned DMN cannot create a roster slot.
    states.push_back(KeyState(Schedule(), banned_hash, EPOCH, SNAPSHOT_HEIGHT, 3));

    const auto roster = BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(10), snapshot, states, {});
    BOOST_REQUIRE(roster);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, 1U);
    BOOST_CHECK(roster->members[0].eligible);
    BOOST_REQUIRE(roster->members[0].child_root);
    BOOST_CHECK(roster->members[1].eligible);
    BOOST_CHECK(!roster->members[1].child_root);
    BOOST_CHECK(IsBitSet(roster->descriptor.valid_members, 0));
    BOOST_CHECK(!IsBitSet(roster->descriptor.valid_members, 1));
    BOOST_CHECK(roster->descriptor.member_root ==
                ComputeQuorumMemberRoot(genesis, *roster));
    BOOST_CHECK(roster->descriptor.child_key_root ==
                ComputeQuorumChildKeyRoot(genesis, *roster));

    FrozenQuorumRoster changed{*roster};
    changed.members[0].pro_tx_hash = NonNullHash(999'999);
    BOOST_CHECK(ComputeQuorumMemberRoot(genesis, changed) !=
                roster->descriptor.member_root);
}

BOOST_AUTO_TEST_CASE(payment_audit_coverage_is_state_independent_and_bounded)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    constexpr uint32_t CANDIDATES{420};
    const uint256 genesis{NonNullHash(80)};
    const uint256 base_hash{NonNullHash(81)};
    const auto snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(82), CANDIDATES)};
    const auto states{KeyStates(CANDIDATES, EPOCH, SNAPSHOT_HEIGHT)};

    std::vector<uint256> root_capable;
    root_capable.reserve(CANDIDATES);
    for (uint32_t member{0}; member < CANDIDATES; ++member) {
        root_capable.push_back(NonNullHash(10'000 + member));
    }
    std::sort(root_capable.begin(), root_capable.end());
    const auto expected{SelectPQPaymentRecoveryMembers(EPOCH, root_capable)};
    BOOST_REQUIRE(expected);
    BOOST_CHECK_EQUAL(expected->count, PAYMENT_AUDIT_RECOVERY_SEATS);

    PQPaymentRecoverySelection recovery;
    const auto roster{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, snapshot, states,
        nullptr, &recovery)};
    BOOST_REQUIRE(roster);
    BOOST_CHECK(recovery == *expected);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, QUORUM_SIZE);
    for (std::size_t slot{0}; slot < recovery.count; ++slot) {
        BOOST_CHECK(
            roster->members[QUORUM_SIZE - recovery.count + slot]
                .pro_tx_hash == recovery.members[slot]);
        BOOST_CHECK(IsBitSet(roster->descriptor.valid_members,
                             QUORUM_SIZE - recovery.count + slot));
    }

    PQPaymentRecoverySelection reverse_recovery;
    const auto reverse_snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(82), CANDIDATES,
        /*reverse=*/true)};
    const auto reversed{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, reverse_snapshot, states,
        nullptr, &reverse_recovery)};
    BOOST_REQUIRE(reversed);
    BOOST_CHECK(reverse_recovery == recovery);
    BOOST_CHECK(reversed->descriptor == roster->descriptor);

    std::set<uint256> covered;
    constexpr std::size_t COVERAGE_EPOCHS{
        (CANDIDATES + PAYMENT_AUDIT_RECOVERY_SEATS - 1) /
        PAYMENT_AUDIT_RECOVERY_SEATS};
    for (std::size_t offset{0}; offset < COVERAGE_EPOCHS; ++offset) {
        const auto selection{SelectPQPaymentRecoveryMembers(
            EPOCH + static_cast<uint32_t>(offset), root_capable)};
        BOOST_REQUIRE(selection);
        BOOST_CHECK_EQUAL(selection->count, PAYMENT_AUDIT_RECOVERY_SEATS);
        for (std::size_t slot{0}; slot < selection->count; ++slot) {
            covered.insert(selection->members[slot]);
        }
    }
    BOOST_CHECK_EQUAL(covered.size(), CANDIDATES);
}

BOOST_AUTO_TEST_CASE(coverage_is_unneeded_when_every_root_capable_member_fits)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    constexpr uint32_t CANDIDATES{600};
    const uint256 genesis{NonNullHash(90)};
    const uint256 base_hash{NonNullHash(91)};
    const auto snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(92), CANDIDATES)};
    constexpr uint32_t ROOTS{300};
    const auto states{KeyStates(ROOTS, EPOCH, SNAPSHOT_HEIGHT)};

    PQPaymentRecoverySelection recovery;
    const auto roster{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, snapshot, states,
        nullptr, &recovery)};
    BOOST_REQUIRE(roster);
    BOOST_CHECK_EQUAL(recovery.count, 0U);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, ROOTS);
    for (const auto& state : states) {
        BOOST_CHECK(ContainsMember(*roster, state.pro_tx_hash));
    }
}

BOOST_AUTO_TEST_CASE(fewer_than_400_unsafe_cutoff_and_duplicate_keys_fail_closed)
{
    constexpr uint32_t EPOCH{4};
    const uint256 genesis{NonNullHash(11)};
    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(12),
        CDeterministicMNList{}, {}, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);

    const auto too_small = Snapshot(2448, NonNullHash(12), QUORUM_SIZE - 1);
    BOOST_CHECK(!BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(13), too_small, {},
        &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);

    auto unsafe_config = BuildConfig();
    unsafe_config.registration_cutoff_blocks =
        unsafe_config.roster_snapshot_lag_blocks - 1;
    BOOST_CHECK(!unsafe_config.IsValid());
    BOOST_CHECK(!BuildFrozenQuorumRoster(
        genesis, unsafe_config, EPOCH, NonNullHash(15),
        Snapshot(2448, NonNullHash(14), QUORUM_SIZE), {}, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INVALID_SCHEDULE);

    const auto frozen_snapshot = Snapshot(2448, NonNullHash(16), QUORUM_SIZE);
    const auto first = BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot, {},
        nullptr);
    BOOST_REQUIRE(first);
    auto key_a = KeyState(Schedule(), first->members[0].pro_tx_hash,
                          EPOCH, 2448, 5);
    auto key_b = KeyState(Schedule(), first->members[1].pro_tx_hash,
                          EPOCH, 2448, 6);
    key_b.frozen_child_roots[0].commitment.tree_id =
        key_a.frozen_child_roots[0].commitment.tree_id;
    key_b.global_key.child_key_commitment.tree_id =
        key_a.global_key.child_key_commitment.tree_id;
    BOOST_REQUIRE(key_b.IsStructurallyValid());
    std::array<OperatorKeyState, 2> duplicate_keys{key_a, key_b};
    BOOST_CHECK(!BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot,
        duplicate_keys, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::DUPLICATE_CHILD_KEY);

    std::array<OperatorKeyState, 2> duplicate_states{key_a, key_a};
    BOOST_CHECK(!BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot,
        duplicate_states, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::DUPLICATE_OPERATOR_STATE);
}

BOOST_AUTO_TEST_CASE(active_builder_uses_canonical_branch_bases_and_snapshots)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    constexpr uint32_t SNAPSHOT_LAG{144};
    const uint256 genesis{NonNullHash(18)};
    IndexChain chain_a(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    IndexChain chain_b(TARGET_HEIGHT, 1800, 0xbeef);

    const QuorumSnapshotLookup lookup = [](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto a = BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_a.Tip(),
        lookup, &error);
    const auto b = BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_b.Tip(),
        lookup, &error);
    BOOST_REQUIRE(a);
    BOOST_REQUIRE(b);
    const std::array<int32_t, ACTIVE_QUORUMS> expected_bases{
        1440, 1728, 2016, 2304};
    const std::array<int32_t, ACTIVE_QUORUMS> expected_snapshots{
        1296, 1584, 1872, 2160};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK_EQUAL((*a)[slot].descriptor.epoch, slot);
        BOOST_CHECK_EQUAL((*a)[slot].descriptor.base_height,
                          expected_bases[slot]);
        BOOST_CHECK_EQUAL((*a)[slot].descriptor.snapshot_height,
                          expected_snapshots[slot]);
        BOOST_CHECK((*a)[slot].descriptor.base_hash ==
                    chain_a.At(expected_bases[slot]).GetBlockHash());
        BOOST_CHECK((*a)[slot].descriptor.snapshot_hash ==
                    chain_a.At(expected_snapshots[slot]).GetBlockHash());
    }
    BOOST_CHECK((*a)[0].descriptor.base_hash == (*b)[0].descriptor.base_hash);
    BOOST_CHECK((*a)[2].descriptor.base_hash != (*b)[2].descriptor.base_hash);
    BOOST_CHECK((*a)[2].descriptor.snapshot_hash != (*b)[2].descriptor.snapshot_hash);

    const QuorumSnapshotLookup wrong_fork = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, chain_a.At(index.nHeight).GetBlockHash(), QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    BOOST_CHECK(!BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_b.Tip(),
        wrong_fork, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);

    BOOST_CHECK(!BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT,
        chain_a.At(TARGET_HEIGHT - 1), lookup, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);

    const QuorumSnapshotLookup unavailable = [](const CBlockIndex&) {
        return std::optional<QuorumSnapshotState>{QuorumSnapshotState{}};
    };
    BOOST_CHECK(!BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_a.Tip(),
        unavailable, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);
}

BOOST_AUTO_TEST_CASE(probation_checkpoint_roots_do_not_select_validators)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    constexpr uint32_t SNAPSHOT_LAG{144};
    const uint256 genesis{NonNullHash(86)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const std::array<int32_t, ACTIVE_QUORUMS> snapshot_heights{
        1296, 1584, 1872, 2160};

    const auto lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), 420);
        const auto epoch{EpochForHeight(
            Schedule(), index.nHeight +
                            static_cast<int32_t>(SNAPSHOT_LAG))};
        if (!epoch) return std::optional<QuorumSnapshotState>{};
        result.operator_key_states =
            KeyStates(420, *epoch, index.nHeight);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    const auto original{BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain.Tip(),
        lookup)};
    BOOST_REQUIRE(original);
    for (std::size_t slot{0}; slot < snapshot_heights.size(); ++slot) {
        chain.indices[snapshot_heights[slot]].pqPaymentProbationStateHash =
            NonNullHash(70'000 + slot);
    }

    const auto checkpointed{BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain.Tip(),
        lookup)};
    BOOST_REQUIRE(checkpointed);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK((*checkpointed)[slot].descriptor ==
                    (*original)[slot].descriptor);
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            BOOST_CHECK((*checkpointed)[slot].members[member].pro_tx_hash ==
                        (*original)[slot].members[member].pro_tx_hash);
        }
    }
}

BOOST_AUTO_TEST_CASE(side_branch_context_is_self_contained_at_target)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    constexpr uint32_t SNAPSHOT_LAG{144};
    const uint256 genesis{NonNullHash(19)};
    // The active branch has five later blocks, but shares no target block with
    // the fully validated side branch after the fork.
    IndexChain active(TARGET_HEIGHT + PQ_CL_SIGN_LAG, 1800, 0xa11ce);
    IndexChain side(TARGET_HEIGHT, 1800, 0x51de);
    const QuorumSnapshotLookup lookup = [](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    const auto rosters = BuildActiveFrozenQuorumRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, side.Tip(), lookup);
    BOOST_REQUIRE(rosters);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = (*rosters)[slot].descriptor;
    }

    ChainLockStatement statement;
    statement.height = TARGET_HEIGHT;
    statement.block_hash = side.Tip().GetBlockHash();
    statement.payment_probation_state_hash = NonNullHash(60'001);
    statement.quorum_context_hash = GetQuorumContextHash(
        genesis, TARGET_HEIGHT, statement.block_hash, descriptors);
    BOOST_CHECK(ValidateFrozenQuorumContext(
        genesis, statement, *rosters));
    BOOST_CHECK(statement.quorum_context_hash != GetQuorumContextHash(
        genesis, TARGET_HEIGHT, active.At(TARGET_HEIGHT).GetBlockHash(),
        descriptors));
}

BOOST_AUTO_TEST_CASE(roster_rotation_requires_finalized_snapshot_after_bootstrap)
{
    auto rosters{std::make_unique<FrozenQuorumRosters>()};
    for (std::size_t slot{0}; slot < rosters->size(); ++slot) {
        (*rosters)[slot].descriptor.epoch = static_cast<uint32_t>(slot);
        (*rosters)[slot].descriptor.snapshot_height = 1'000 + slot;
        (*rosters)[slot].descriptor.snapshot_hash = NonNullHash(900 + slot);
    }

    std::size_t lookups{0};
    BOOST_CHECK(AreSigningRosterTransitionsFinalized(
        *rosters, [&](int32_t, const uint256&) {
            ++lookups;
            return false;
        }));
    BOOST_CHECK_EQUAL(lookups, 0U);

    rosters->back().descriptor.epoch = ACTIVE_QUORUMS;
    const int32_t required_height{
        rosters->back().descriptor.snapshot_height};
    const uint256 required_hash{rosters->back().descriptor.snapshot_hash};
    BOOST_CHECK(!AreSigningRosterTransitionsFinalized(
        *rosters, [](int32_t, const uint256&) { return false; }));
    BOOST_CHECK(AreSigningRosterTransitionsFinalized(
        *rosters, [&](int32_t height, const uint256& hash) {
            return height == required_height && hash == required_hash;
        }));
    BOOST_CHECK(!AreSigningRosterTransitionsFinalized(*rosters, {}));
}

BOOST_AUTO_TEST_SUITE_END()
