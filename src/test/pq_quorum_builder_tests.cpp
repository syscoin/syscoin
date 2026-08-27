// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/sha256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <ostream>
#include <span>
#include <thread>
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

std::shared_ptr<const std::vector<OperatorKeyState>> SharedOperatorStates(
    std::vector<OperatorKeyState> states = {})
{
    return std::make_shared<const std::vector<OperatorKeyState>>(
        std::move(states));
}

std::vector<uint256> ScoreOrderedMembers(uint32_t count,
                                         const uint256& modifier)
{
    struct Scored {
        arith_uint256 score;
        CDeterministicMNCPtr dmn;
    };

    std::vector<Scored> scored;
    scored.reserve(count);
    for (uint32_t tag{0}; tag < count; ++tag) {
        auto dmn{Member(tag)};
        uint256 score_hash;
        CSHA256 hasher;
        hasher.Write(dmn->pdmnState->confirmedHashWithProRegTxHash.begin(),
                     dmn->pdmnState->confirmedHashWithProRegTxHash.size());
        hasher.Write(modifier.begin(), modifier.size());
        hasher.Finalize(score_hash.begin());
        scored.push_back({UintToArith256(score_hash), std::move(dmn)});
    }
    std::sort(scored.begin(), scored.end(),
              [](const Scored& lhs, const Scored& rhs) {
                  if (lhs.score != rhs.score) return lhs.score > rhs.score;
                  return rhs.dmn->collateralOutpoint <
                         lhs.dmn->collateralOutpoint;
              });

    std::vector<uint256> ordered;
    ordered.reserve(scored.size());
    for (const auto& candidate : scored) {
        ordered.push_back(candidate.dmn->proTxHash);
    }
    return ordered;
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

BOOST_AUTO_TEST_CASE(more_than_400_candidates_select_top_scores_deterministically)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    constexpr uint32_t ROOT_CAPABLE{420};
    constexpr uint32_t CANDIDATES{440};
    const uint256 genesis{NonNullHash(80)};
    const uint256 base_hash{NonNullHash(81)};
    const auto snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(82), CANDIDATES)};
    const auto states{KeyStates(ROOT_CAPABLE, EPOCH, SNAPSHOT_HEIGHT)};
    const auto modifier{GetPQQuorumModifier(genesis, EPOCH, base_hash)};
    BOOST_REQUIRE(modifier);
    const auto expected{ScoreOrderedMembers(ROOT_CAPABLE, *modifier)};

    const auto roster{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, snapshot, states)};
    BOOST_REQUIRE(roster);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, QUORUM_SIZE);
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(roster->members[slot].pro_tx_hash == expected[slot]);
    }
    for (std::size_t candidate{QUORUM_SIZE}; candidate < ROOT_CAPABLE;
         ++candidate) {
        BOOST_CHECK(!ContainsMember(*roster, expected[candidate]));
    }
    for (uint32_t candidate{ROOT_CAPABLE}; candidate < CANDIDATES;
         ++candidate) {
        BOOST_CHECK(!ContainsMember(
            *roster, NonNullHash(10'000 + candidate)));
    }

    const auto reverse_snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(82), CANDIDATES,
        /*reverse=*/true)};
    const auto reversed{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, reverse_snapshot, states)};
    BOOST_REQUIRE(reversed);
    BOOST_CHECK(reversed->descriptor == roster->descriptor);
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(reversed->members[slot].pro_tx_hash == expected[slot]);
    }
}

BOOST_AUTO_TEST_CASE(root_capable_members_rank_ahead_when_they_fit)
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

    const auto roster{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, base_hash, snapshot, states)};
    BOOST_REQUIRE(roster);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, ROOTS);
    for (const auto& state : states) {
        BOOST_CHECK(ContainsMember(*roster, state.pro_tx_hash));
    }
    for (std::size_t slot{0}; slot < ROOTS; ++slot) {
        BOOST_CHECK(roster->members[slot].child_root.has_value());
    }
    for (std::size_t slot{ROOTS}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(!roster->members[slot].child_root.has_value());
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

    auto epoch_boundary_config = BuildConfig(Schedule().epoch_blocks);
    BOOST_CHECK(epoch_boundary_config.IsValid());
    auto multi_epoch_lag_config =
        BuildConfig(Schedule().epoch_blocks + 1);
    BOOST_CHECK(!multi_epoch_lag_config.IsValid());

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
        result.operator_key_states = SharedOperatorStates();
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
        result.operator_key_states = SharedOperatorStates();
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

BOOST_AUTO_TEST_CASE(active_roster_cache_reuses_exact_branch_contexts)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t SECOND_TARGET{2310};
    const uint256 genesis{NonNullHash(20)};
    IndexChain canonical(SECOND_TARGET, SECOND_TARGET + 1, 0);
    IndexChain fork_after_base(SECOND_TARGET, 2306, 0xa11ce);
    IndexChain fork_at_base(SECOND_TARGET, 2304, 0x51de);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = SharedOperatorStates();
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    BOOST_CHECK(cache->GenesisHash() == genesis);
    BOOST_CHECK(cache->Config() == BuildConfig());

    QuorumBuildError error{QuorumBuildError::INVALID_ARGUMENT};
    const auto first{cache->GetActive(
        FIRST_TARGET, canonical.Tip(), &error)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto same_set{cache->GetActive(
        SECOND_TARGET, canonical.Tip(), &error)};
    BOOST_REQUIRE(same_set);
    BOOST_CHECK(first == same_set);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto post_base_fork{cache->GetActive(
        SECOND_TARGET, fork_after_base.Tip(), &error)};
    BOOST_REQUIRE(post_base_fork);
    BOOST_CHECK(post_base_fork == first);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto base_fork{cache->GetActive(
        FIRST_TARGET, fork_at_base.Tip(), &error)};
    BOOST_REQUIRE(base_fork);
    BOOST_CHECK(base_fork != first);
    BOOST_CHECK_EQUAL(lookups, 2 * ACTIVE_QUORUMS);

    BOOST_CHECK(!cache->GetActive(
        FIRST_TARGET + 1, canonical.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_TARGET_HEIGHT);
    BOOST_CHECK_EQUAL(lookups, 2 * ACTIVE_QUORUMS);
    BOOST_CHECK(!cache->GetActive(
        FIRST_TARGET, canonical.At(FIRST_TARGET - 1), &error));
    BOOST_CHECK(error == QuorumBuildError::MISSING_BRANCH_ANCESTOR);
    BOOST_CHECK_EQUAL(lookups, 2 * ACTIVE_QUORUMS);

    BOOST_REQUIRE(cache->LookupSnapshot(canonical.At(1296)));
    BOOST_REQUIRE(cache->LookupSnapshot(canonical.At(1296)));
    BOOST_CHECK_EQUAL(lookups, 2 * ACTIVE_QUORUMS + 2);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_retries_failures_and_can_be_disabled)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    const uint256 genesis{NonNullHash(21)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::size_t lookups{0};
    bool fail_next{true};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        if (fail_next) {
            fail_next = false;
            return std::optional<QuorumSnapshotState>{};
        }
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = SharedOperatorStates();
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!cache->GetActive(
        TARGET_HEIGHT, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
    BOOST_CHECK_EQUAL(lookups, 1U);

    const auto retry{cache->GetActive(TARGET_HEIGHT, chain.Tip(), &error)};
    BOOST_REQUIRE(retry);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);
    BOOST_CHECK(cache->GetActive(TARGET_HEIGHT, chain.Tip()) == retry);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);

    std::size_t uncached_lookups{0};
    const QuorumSnapshotLookup uncached_lookup =
        [&](const CBlockIndex& index) {
            ++uncached_lookups;
            QuorumSnapshotState result;
            result.deterministic_mns = Snapshot(
                index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
            result.operator_key_states = SharedOperatorStates();
            return std::optional<QuorumSnapshotState>{std::move(result)};
        };
    const auto uncached{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), uncached_lookup,
        /*cache_results=*/false)};
    BOOST_REQUIRE(uncached);
    const auto uncached_first{
        uncached->GetActive(TARGET_HEIGHT, chain.Tip())};
    const auto uncached_second{
        uncached->GetActive(TARGET_HEIGHT, chain.Tip())};
    BOOST_REQUIRE(uncached_first);
    BOOST_REQUIRE(uncached_second);
    BOOST_CHECK(uncached_first != uncached_second);
    BOOST_CHECK_EQUAL(uncached_lookups, 2 * ACTIVE_QUORUMS);

    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        uint256{}, BuildConfig(), uncached_lookup));
    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        genesis, QuorumBuildConfig{}, uncached_lookup));
    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), QuorumSnapshotLookup{}));
}

BOOST_AUTO_TEST_CASE(active_roster_cache_converges_concurrent_builds)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    constexpr int32_t FIRST_SNAPSHOT_HEIGHT{1296};
    const uint256 genesis{NonNullHash(23)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::atomic<std::size_t> lookups{0};
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    std::size_t arrivals{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        lookups.fetch_add(1, std::memory_order_relaxed);
        if (index.nHeight == FIRST_SNAPSHOT_HEIGHT) {
            std::unique_lock lock{barrier_mutex};
            ++arrivals;
            barrier_cv.notify_all();
            if (!barrier_cv.wait_for(
                    lock, std::chrono::seconds{30},
                    [&] { return arrivals == 2; })) {
                return std::optional<QuorumSnapshotState>{};
            }
        }
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = SharedOperatorStates();
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    std::array<FrozenQuorumRostersPtr, 2> results;
    std::thread first{[&] {
        results[0] = cache->GetActive(TARGET_HEIGHT, chain.Tip());
    }};
    std::thread second{[&] {
        results[1] = cache->GetActive(TARGET_HEIGHT, chain.Tip());
    }};
    first.join();
    second.join();

    BOOST_REQUIRE(results[0]);
    BOOST_REQUIRE(results[1]);
    BOOST_CHECK(results[0] == results[1]);
    BOOST_CHECK_EQUAL(lookups.load(std::memory_order_relaxed),
                      2 * ACTIVE_QUORUMS);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_eviction_preserves_reader_lifetime)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t CONTEXT_STRIDE{
        static_cast<int32_t>(PQ_EPOCH_ALIGNMENT)};
    constexpr std::size_t CONTEXTS{
        FROZEN_QUORUM_ROSTER_CACHE_CAPACITY + 1};
    constexpr int32_t LAST_TARGET{
        FIRST_TARGET +
        static_cast<int32_t>(CONTEXTS - 1) * CONTEXT_STRIDE};
    const uint256 genesis{NonNullHash(22)};
    IndexChain chain(LAST_TARGET, LAST_TARGET + 1, 0);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = SharedOperatorStates();
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const auto retained{cache->GetActive(
        FIRST_TARGET, chain.Tip())};
    BOOST_REQUIRE(retained);
    const auto retained_descriptor{retained->front().descriptor};
    for (std::size_t context{1}; context < CONTEXTS; ++context) {
        const int32_t target{
            FIRST_TARGET + static_cast<int32_t>(context) * CONTEXT_STRIDE};
        BOOST_REQUIRE(cache->GetActive(target, chain.Tip()));
    }
    BOOST_CHECK_EQUAL(lookups, CONTEXTS * ACTIVE_QUORUMS);

    const auto rebuilt{cache->GetActive(FIRST_TARGET, chain.Tip())};
    BOOST_REQUIRE(rebuilt);
    BOOST_CHECK(rebuilt != retained);
    BOOST_CHECK(rebuilt->front().descriptor == retained_descriptor);
    BOOST_CHECK(retained->front().descriptor == retained_descriptor);
    BOOST_CHECK_EQUAL(lookups, (CONTEXTS + 1) * ACTIVE_QUORUMS);
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
        result.operator_key_states = SharedOperatorStates(
            KeyStates(420, *epoch, index.nHeight));
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
        result.operator_key_states = SharedOperatorStates();
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
    statement.previous_chainlock_height = TARGET_HEIGHT - PQ_CL_SIGN_LAG;
    statement.previous_chainlock_hash =
        side.At(statement.previous_chainlock_height).GetBlockHash();
    statement.payment_probation_state_hash = NonNullHash(60'001);
    statement.quorum_context_hash = GetQuorumContextHash(
        genesis, TARGET_HEIGHT, statement.block_hash, descriptors);
    BOOST_CHECK(ValidateFrozenQuorumContext(
        genesis, statement, *rosters, 0b0111));
    BOOST_CHECK(!ValidateFrozenQuorumContext(
        genesis, statement, *rosters, 0b1111));
    BOOST_CHECK(statement.quorum_context_hash != GetQuorumContextHash(
        genesis, TARGET_HEIGHT, active.At(TARGET_HEIGHT).GetBlockHash(),
        descriptors));
}

BOOST_AUTO_TEST_CASE(roster_rotation_derives_contiguous_authorization_prefix)
{
    auto rosters{std::make_unique<FrozenQuorumRosters>()};
    for (std::size_t slot{0}; slot < rosters->size(); ++slot) {
        (*rosters)[slot].descriptor.epoch = static_cast<uint32_t>(slot);
        (*rosters)[slot].descriptor.base_height = 1'100 + slot;
        (*rosters)[slot].descriptor.base_hash = NonNullHash(800 + slot);
        (*rosters)[slot].descriptor.snapshot_height = 1'000 + slot;
        (*rosters)[slot].descriptor.snapshot_hash = NonNullHash(900 + slot);
    }

    std::size_t lookups{0};
    BOOST_CHECK_EQUAL(GetSigningRosterAuthorizationMask(
        *rosters, [&](int32_t, const uint256&) {
            ++lookups;
            return false;
        }), 0);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);
    lookups = 0;
    BOOST_CHECK_EQUAL(GetSigningRosterAuthorizationMask(
        *rosters, [&](int32_t height, const uint256& hash) {
            ++lookups;
            for (const auto& roster : *rosters) {
                if (height == roster.descriptor.base_height &&
                    hash == roster.descriptor.base_hash) {
                    return true;
                }
            }
            return false;
        }), 0b1111);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    rosters->back().descriptor.epoch = ACTIVE_QUORUMS;
    const int32_t required_height{
        rosters->back().descriptor.snapshot_height};
    const uint256 required_hash{rosters->back().descriptor.snapshot_hash};
    BOOST_CHECK_EQUAL(GetSigningRosterAuthorizationMask(
        *rosters, [&](int32_t height, const uint256& hash) {
            for (std::size_t slot{0}; slot + 1 < rosters->size(); ++slot) {
                const auto& descriptor{(*rosters)[slot].descriptor};
                if (height == descriptor.base_height &&
                    hash == descriptor.base_hash) {
                    return true;
                }
            }
            return false;
        }), 0b0111);
    BOOST_CHECK(IsSigningRosterAuthorizationMask(0b0111));
    BOOST_CHECK(IsSigningRosterAuthorizationMask(0b1111));
    BOOST_CHECK(!IsSigningRosterAuthorizationMask(0b0011));
    BOOST_CHECK(!IsSigningRosterAuthorizationMask(0b1011));
    BOOST_CHECK(!IsSigningRosterAuthorizationMask(0b10111));

    BOOST_CHECK_EQUAL(GetSigningRosterAuthorizationMask(
        *rosters, [&](int32_t height, const uint256& hash) {
            if (height == required_height && hash == required_hash) {
                return true;
            }
            const auto& first{(*rosters)[0].descriptor};
            return height == first.base_height && hash == first.base_hash;
        }), 0);
    BOOST_CHECK_EQUAL(
        GetSigningRosterAuthorizationMask(*rosters, {}), 0);
}

BOOST_AUTO_TEST_SUITE_END()
