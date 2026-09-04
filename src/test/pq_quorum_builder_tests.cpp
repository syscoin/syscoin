// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_quorum_builder.h>

#include <arith_uint256.h>
#include <chain.h>
#include <crypto/sha256.h>
#include <streams.h>
#include <test/pq_test_util.h>

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
#include <set>
#include <span>
#include <stdexcept>
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

std::vector<uint8_t> EncodeRecoveryUniverseUnchecked(
    uint16_t version,
    const uint256& genesis_hash,
    const RecoveryRosterAuthoritySource& source,
    int32_t snapshot_height,
    const uint256& snapshot_hash,
    std::span<const RecoveryUniverseMember> members,
    uint32_t encoded_member_count,
    const uint256& members_hash,
    const uint256& capsule_id)
{
    DataStream stream{SER_DISK};
    stream << version << genesis_hash << source << snapshot_height
           << snapshot_hash
           << GetRecoveryUniverseSourceId(genesis_hash, source)
           << encoded_member_count;
    for (const auto& member : members) stream << member;
    stream << members_hash << capsule_id;
    return {UCharCast(stream.data()),
            UCharCast(stream.data() + stream.size())};
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
                            uint256 cached_score_seed = uint256{},
                            uint256 collateral_hash = uint256{})
{
    auto dmn = std::make_shared<CDeterministicMN>(tag + 1);
    dmn->proTxHash = NonNullHash(10'000 + tag);
    dmn->collateralOutpoint = COutPoint(
        collateral_hash.IsNull() ? NonNullHash(20'000 + tag)
                                 : collateral_hash,
        tag + 1);

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

CDeterministicMNList SnapshotFromMembers(
    int32_t height,
    const uint256& block_hash,
    std::span<const CDeterministicMNCPtr> members)
{
    CDeterministicMNList snapshot(
        block_hash, height, static_cast<uint32_t>(members.size()));
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

RosterResetVerificationPolicy ResetPolicy()
{
    return RosterResetVerificationPolicy{
        Schedule(), BTCCScheduleConfig{.candidate_origin = 2305}, 2304};
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

RosterBeaconSeed ReadyBeaconSeed(uint32_t epoch, uint64_t salt = 0)
{
    const auto base_height{EpochBaseHeight(Schedule(), epoch)};
    BOOST_REQUIRE(base_height);
    RosterBeaconSeed seed;
    seed.anchor_kind = RosterBeaconAnchorKind::NORMAL;
    seed.state = RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = BTCCursor{
        *base_height - 1,
        NonNullHash(900'000 + epoch, salt),
        NonNullHash(910'000 + epoch, salt)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(920'000 + epoch, salt);
    BOOST_REQUIRE(seed.IsReady());
    return seed;
}

ActiveRosterBeaconBundle BeaconBundle(uint32_t newest_epoch,
                                      uint64_t salt = 0)
{
    BOOST_REQUIRE_GE(newest_epoch,
                     static_cast<uint32_t>(ACTIVE_QUORUMS - 1));
    ActiveRosterBeaconBundle bundle;
    const uint32_t first_epoch{
        newest_epoch - static_cast<uint32_t>(ACTIVE_QUORUMS - 1)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        bundle.seeds[slot] = ReadyBeaconSeed(
            first_epoch + static_cast<uint32_t>(slot), salt);
    }
    bundle.recovery_authority_source.normal_beacon = bundle.seeds.back();
    BOOST_REQUIRE(bundle.IsForNewestEpoch(newest_epoch));
    return bundle;
}

ActiveRosterBeaconBundle BeaconBundleAtHeight(int32_t target_height,
                                              uint64_t salt = 0)
{
    const auto epochs{ActiveEpochsAtHeight(Schedule(), target_height)};
    BOOST_REQUIRE(epochs);
    return BeaconBundle(epochs->back().epoch, salt);
}

RecoveryRosterAuthoritySource RecoverySourceForChain(
    const CBlockIndex& branch_tip,
    uint32_t source_epoch,
    uint64_t salt = 0)
{
    RecoveryRosterAuthoritySource source;
    source.normal_beacon = ReadyBeaconSeed(source_epoch, salt);
    const CBlockIndex* anchor{branch_tip.GetAncestor(
        source.normal_beacon.anchor_cursor.sys_height)};
    BOOST_REQUIRE(anchor);
    source.normal_beacon.anchor_cursor.sys_hash = anchor->GetBlockHash();
    BOOST_REQUIRE(source.IsStructurallyValid());
    return source;
}

ActiveRosterBeaconBundle RecoveryBeaconBundleAtHeight(
    int32_t target_height,
    const RecoveryRosterAuthoritySource& source)
{
    const auto epochs{ActiveEpochsAtHeight(Schedule(), target_height)};
    BOOST_REQUIRE(epochs);
    const auto window{MakeRecoveryRosterBeaconWindow(
        source, epochs->back().epoch)};
    BOOST_REQUIRE(window);
    return window->active;
}

std::unique_ptr<FrozenQuorumRoster> BuildTestRoster(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    uint32_t epoch,
    const uint256& base_hash,
    const CDeterministicMNList& snapshot,
    std::span<const OperatorKeyState> operator_key_states,
    QuorumBuildError* error = nullptr)
{
    return BuildFrozenQuorumRoster(
        genesis_hash, config, epoch, base_hash, ReadyBeaconSeed(epoch),
        snapshot, operator_key_states, error);
}

FrozenQuorumRostersPtr BuildTestActiveRosters(
    const uint256& genesis_hash,
    const QuorumBuildConfig& config,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    const QuorumSnapshotLookup& snapshot_lookup,
    QuorumBuildError* error = nullptr)
{
    return BuildActiveFrozenQuorumRosters(
        genesis_hash, config, target_height, branch_tip,
        BeaconBundleAtHeight(target_height), snapshot_lookup, error);
}

FrozenQuorumRostersPtr GetTestActive(
    const FrozenQuorumRosterCachePtr& cache,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    QuorumBuildError* error = nullptr)
{
    return cache->GetActive(target_height, branch_tip,
                            BeaconBundleAtHeight(target_height), error);
}

VerifiedRosterSetPtr GetTestVerifiedActive(
    const FrozenQuorumRosterCachePtr& cache,
    int32_t target_height,
    const CBlockIndex& branch_tip,
    QuorumBuildError* error = nullptr)
{
    return cache->GetVerifiedActive(
        target_height, branch_tip, BeaconBundleAtHeight(target_height), error);
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

std::vector<OperatorKeyState> GlobalKeyStates(
    uint32_t count,
    uint32_t first_epoch,
    int32_t snapshot_height)
{
    std::vector<OperatorKeyState> states;
    states.reserve(count);
    for (uint32_t member{0}; member < count; ++member) {
        states.push_back(KeyState(
            Schedule(), NonNullHash(10'000 + member), first_epoch,
            snapshot_height, member + 1, /*include_child=*/false));
    }
    return states;
}

std::vector<OperatorKeyState> RecoveryTargetKeyStates(
    uint32_t count,
    int32_t target_height)
{
    auto states{GlobalKeyStates(count, /*first_epoch=*/0, target_height)};
    for (auto& state : states) {
        for (uint32_t epoch{state.schedule.first_retained_frozen_epoch};
             epoch < state.schedule.first_mutable_epoch; ++epoch) {
            state.frozen_child_roots.push_back(FrozenChildRootRecord{
                state.pro_tx_hash,
                state.global_key.key_version,
                epoch,
                state.global_key.child_key_commitment});
        }
        BOOST_REQUIRE(state.IsStructurallyValid());
    }
    return states;
}

std::shared_ptr<const std::vector<OperatorKeyState>> SharedOperatorStates(
    std::vector<OperatorKeyState> states = {})
{
    return std::make_shared<const std::vector<OperatorKeyState>>(
        std::move(states));
}

std::shared_ptr<const std::vector<OperatorKeyState>>
RootedOperatorStatesForSnapshot(
    const CBlockIndex& index,
    uint32_t count,
    uint32_t snapshot_lag = 144)
{
    const auto epoch{EpochForHeight(
        Schedule(), index.nHeight + static_cast<int32_t>(snapshot_lag))};
    if (!epoch) throw std::runtime_error{"invalid roster snapshot height"};
    return SharedOperatorStates(KeyStates(count, *epoch, index.nHeight));
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

std::vector<uint256> FullSortRosterOracle(
    std::span<const CDeterministicMNCPtr> members,
    const uint256& modifier,
    const std::set<uint256>& root_capable)
{
    struct Scored {
        arith_uint256 score;
        CDeterministicMNCPtr dmn;
        bool root_capable{false};
    };

    std::vector<Scored> scored;
    scored.reserve(members.size());
    for (const auto& dmn : members) {
        if (!CDeterministicMNList::IsMNValid(*dmn) ||
            dmn->pdmnState->confirmedHash.IsNull() ||
            !root_capable.contains(dmn->proTxHash)) {
            continue;
        }
        uint256 score_hash;
        CSHA256 hasher;
        hasher.Write(dmn->pdmnState->confirmedHashWithProRegTxHash.begin(),
                     dmn->pdmnState->confirmedHashWithProRegTxHash.size());
        hasher.Write(modifier.begin(), modifier.size());
        hasher.Finalize(score_hash.begin());
        scored.push_back({UintToArith256(score_hash), dmn, true});
    }
    std::sort(scored.begin(), scored.end(),
              [](const Scored& lhs, const Scored& rhs) {
                  if (lhs.root_capable != rhs.root_capable) {
                      return lhs.root_capable;
                  }
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

bool SameRosterSet(const FrozenQuorumRosters& first,
                   const FrozenQuorumRosters& second)
{
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if (first[slot].descriptor != second[slot].descriptor) return false;
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            const auto& lhs{first[slot].members[member]};
            const auto& rhs{second[slot].members[member]};
            if (lhs.pro_tx_hash != rhs.pro_tx_hash ||
                lhs.eligible != rhs.eligible ||
                lhs.child_root != rhs.child_root) {
                return false;
            }
        }
    }
    return true;
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

BOOST_AUTO_TEST_CASE(base_hash_cannot_grind_fixed_snapshot_and_beacon)
{
    const uint256 genesis{NonNullHash(1)};
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    const auto snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(2), QUORUM_SIZE + 20)};
    const auto states{KeyStates(
        QUORUM_SIZE + 20, EPOCH, SNAPSHOT_HEIGHT)};
    const auto seed{ReadyBeaconSeed(EPOCH)};
    const auto first{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(3), seed, snapshot,
        states)};
    const auto changed_base{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(4), seed, snapshot,
        states)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(changed_base);
    BOOST_CHECK(first->descriptor.base_hash !=
                changed_base->descriptor.base_hash);
    BOOST_CHECK(first->descriptor.roster_beacon_hash ==
                changed_base->descriptor.roster_beacon_hash);
    BOOST_CHECK(first->descriptor.member_root ==
                changed_base->descriptor.member_root);
    BOOST_CHECK(first->descriptor.child_key_root ==
                changed_base->descriptor.child_key_root);
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(first->members[slot].pro_tx_hash ==
                    changed_base->members[slot].pro_tx_hash);
    }

    auto changed_future{seed};
    changed_future.future_btc_hash = NonNullHash(5);
    const auto first_modifier{GetPQQuorumModifier(
        genesis, EPOCH, SNAPSHOT_HEIGHT, snapshot.GetBlockHash(), seed)};
    const auto changed_modifier{GetPQQuorumModifier(
        genesis, EPOCH, SNAPSHOT_HEIGHT, snapshot.GetBlockHash(),
        changed_future)};
    BOOST_REQUIRE(first_modifier);
    BOOST_REQUIRE(changed_modifier);
    BOOST_CHECK(*first_modifier != *changed_modifier);
    const auto changed_seed{BuildFrozenQuorumRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(3), changed_future,
        snapshot, states)};
    BOOST_REQUIRE(changed_seed);
    BOOST_CHECK(first->descriptor.roster_beacon_hash !=
                changed_seed->descriptor.roster_beacon_hash);
    bool identical_order{true};
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        identical_order &= first->members[slot].pro_tx_hash ==
                           changed_seed->members[slot].pro_tx_hash;
    }
    BOOST_CHECK(!identical_order);
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
    const auto states{KeyStates(QUORUM_SIZE, EPOCH, SNAPSHOT_HEIGHT)};

    const auto a = BuildTestRoster(
        genesis, BuildConfig(), EPOCH, base_hash, forward, states, {});
    const auto b = BuildTestRoster(
        genesis, BuildConfig(), EPOCH, base_hash, reverse, states, {});
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

BOOST_AUTO_TEST_CASE(normal_rosters_require_400_exact_frozen_roots)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    const uint256 genesis{NonNullHash(8)};
    const auto snapshot = Snapshot(SNAPSHOT_HEIGHT, NonNullHash(9), QUORUM_SIZE,
                                   false, false,
                                   /*add_banned_and_unconfirmed=*/true);
    const uint256 banned_hash{NonNullHash(10'000 + QUORUM_SIZE)};
    const uint256 unconfirmed_hash{NonNullHash(10'001 + QUORUM_SIZE)};

    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(10), snapshot, {}, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);

    auto states{KeyStates(QUORUM_SIZE, EPOCH, SNAPSHOT_HEIGHT)};
    states.pop_back();
    states.push_back(KeyState(
        Schedule(), banned_hash, EPOCH, SNAPSHOT_HEIGHT, QUORUM_SIZE + 1));
    BOOST_CHECK(!BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(10), snapshot, states,
        &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);

    states = KeyStates(QUORUM_SIZE, EPOCH, SNAPSHOT_HEIGHT);
    const auto roster = BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(10), snapshot, states,
        &error);
    BOOST_REQUIRE(roster);
    BOOST_CHECK_EQUAL(error, QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(roster->descriptor.valid_count, QUORUM_SIZE);
    BOOST_CHECK_EQUAL(FindMember(*roster, banned_hash), QUORUM_SIZE);
    BOOST_CHECK_EQUAL(FindMember(*roster, unconfirmed_hash), QUORUM_SIZE);
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(roster->members[slot].eligible);
        BOOST_CHECK(roster->members[slot].child_root.has_value());
        BOOST_CHECK(IsBitSet(roster->descriptor.valid_members, slot));
    }
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
    const auto modifier{GetPQQuorumModifier(
        genesis, EPOCH, SNAPSHOT_HEIGHT, snapshot.GetBlockHash(),
        ReadyBeaconSeed(EPOCH))};
    BOOST_REQUIRE(modifier);
    const auto expected{ScoreOrderedMembers(ROOT_CAPABLE, *modifier)};

    const auto roster{BuildTestRoster(
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
    const auto reversed{BuildTestRoster(
        genesis, BuildConfig(), EPOCH, base_hash, reverse_snapshot, states)};
    BOOST_REQUIRE(reversed);
    BOOST_CHECK(reversed->descriptor == roster->descriptor);
    for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
        BOOST_CHECK(reversed->members[slot].pro_tx_hash == expected[slot]);
    }
}

BOOST_AUTO_TEST_CASE(partial_sort_matches_full_sort_oracle_at_cutoff)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    struct Scenario {
        uint32_t candidates;
        uint32_t root_capable;
        uint32_t score_buckets;
    };
    constexpr std::array<Scenario, 4> scenarios{{
        {401, 401, 0},
        {517, 417, 23},
        {803, 403, 1},
        {1'009, 617, 97},
    }};

    for (std::size_t scenario_index{0};
         scenario_index < scenarios.size(); ++scenario_index) {
        const auto& scenario{scenarios[scenario_index]};
        const bool tied_cutoff{scenario_index == 2};
        const uint256 shared_collateral_hash{
            tied_cutoff ? NonNullHash(700'000 + scenario_index) : uint256{}};
        std::vector<CDeterministicMNCPtr> members;
        members.reserve(scenario.candidates);
        for (uint32_t tag{0}; tag < scenario.candidates; ++tag) {
            const uint256 score_seed{
                scenario.score_buckets == 0
                    ? uint256{}
                    : NonNullHash(710'000 + scenario_index * 1'000 +
                                  tag % scenario.score_buckets)};
            members.push_back(Member(tag, false, true, score_seed,
                                     shared_collateral_hash));
        }

        std::set<uint256> root_capable;
        std::vector<OperatorKeyState> states;
        states.reserve(scenario.root_capable);
        const uint32_t root_shift{
            tied_cutoff
                ? 0U
                : static_cast<uint32_t>((scenario_index * 137) %
                                        scenario.candidates)};
        for (uint32_t tag{0}; tag < scenario.candidates; ++tag) {
            const bool has_root{
                (tag + scenario.candidates - root_shift) %
                    scenario.candidates <
                scenario.root_capable};
            if (!has_root) continue;
            const uint256 pro_tx_hash{NonNullHash(10'000 + tag)};
            root_capable.insert(pro_tx_hash);
            states.push_back(KeyState(
                Schedule(), pro_tx_hash, EPOCH, SNAPSHOT_HEIGHT,
                static_cast<uint32_t>(scenario_index * 2'000 + tag + 1)));
        }
        BOOST_REQUIRE_EQUAL(root_capable.size(), scenario.root_capable);

        const uint256 genesis{NonNullHash(720'000 + scenario_index)};
        const uint256 base_hash{NonNullHash(730'000 + scenario_index)};
        const uint256 snapshot_hash{NonNullHash(740'000 + scenario_index)};
        const auto modifier{GetPQQuorumModifier(
            genesis, EPOCH, SNAPSHOT_HEIGHT, snapshot_hash,
            ReadyBeaconSeed(EPOCH))};
        BOOST_REQUIRE(modifier);
        const auto expected{
            FullSortRosterOracle(members, *modifier, root_capable)};
        BOOST_REQUIRE_EQUAL(expected.size(), scenario.root_capable);
        BOOST_REQUIRE_GT(expected.size(), QUORUM_SIZE);

        std::vector<std::vector<CDeterministicMNCPtr>> permutations;
        permutations.push_back(members);
        permutations.push_back(members);
        std::reverse(permutations.back().begin(), permutations.back().end());
        permutations.push_back(members);
        std::rotate(permutations.back().begin(),
                    permutations.back().begin() +
                        scenario.candidates / 3,
                    permutations.back().end());
        permutations.emplace_back();
        permutations.back().reserve(members.size());
        for (std::size_t index{0}; index < members.size(); index += 2) {
            permutations.back().push_back(members[index]);
        }
        for (std::size_t index{1}; index < members.size(); index += 2) {
            permutations.back().push_back(members[index]);
        }

        for (std::size_t permutation{0}; permutation < permutations.size();
             ++permutation) {
            const auto snapshot{SnapshotFromMembers(
                SNAPSHOT_HEIGHT, snapshot_hash, permutations[permutation])};
            auto ordered_states{states};
            if ((permutation & 1U) != 0) {
                std::reverse(ordered_states.begin(), ordered_states.end());
            }
            const auto roster{BuildTestRoster(
                genesis, BuildConfig(), EPOCH, base_hash, snapshot,
                ordered_states)};
            BOOST_REQUIRE(roster);
            BOOST_CHECK_EQUAL(roster->descriptor.valid_count, QUORUM_SIZE);
            for (std::size_t slot{0}; slot < QUORUM_SIZE; ++slot) {
                BOOST_CHECK(roster->members[slot].pro_tx_hash ==
                            expected[slot]);
                BOOST_CHECK(roster->members[slot].child_root.has_value());
            }
            BOOST_CHECK(ContainsMember(*roster, expected[QUORUM_SIZE - 1]));
            BOOST_CHECK(!ContainsMember(*roster, expected[QUORUM_SIZE]));
        }

        if (tied_cutoff) {
            // All 403 root-capable candidates have the same score. The last
            // selected and first rejected candidates are therefore fixed only
            // by their unique collateral indices.
            BOOST_CHECK(expected[QUORUM_SIZE - 1] == NonNullHash(10'003));
            BOOST_CHECK(expected[QUORUM_SIZE] == NonNullHash(10'002));
        }
    }

    // The final comparator key cannot tie for a valid deterministic-MN list.
    // Duplicate collateral outpoints are rejected while constructing it.
    const auto first{Member(50'000, false, true, NonNullHash(750'000))};
    auto duplicate{
        std::make_shared<CDeterministicMN>(*Member(
            50'001, false, true, NonNullHash(750'000)))};
    duplicate->collateralOutpoint = first->collateralOutpoint;
    CDeterministicMNList duplicate_snapshot(
        NonNullHash(750'001), SNAPSHOT_HEIGHT, 2);
    duplicate_snapshot.AddMN(first);
    BOOST_CHECK_THROW(duplicate_snapshot.AddMN(duplicate), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rootless_candidates_never_fill_normal_roster)
{
    constexpr uint32_t EPOCH{4};
    constexpr int32_t SNAPSHOT_HEIGHT{2448};
    constexpr uint32_t CANDIDATES{600};
    const uint256 genesis{NonNullHash(90)};
    const uint256 base_hash{NonNullHash(91)};
    const auto snapshot{Snapshot(
        SNAPSHOT_HEIGHT, NonNullHash(92), CANDIDATES)};
    constexpr uint32_t ROOTS{QUORUM_SIZE - 1};
    const auto states{KeyStates(ROOTS, EPOCH, SNAPSHOT_HEIGHT)};

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto roster{BuildTestRoster(
        genesis, BuildConfig(), EPOCH, base_hash, snapshot, states, &error)};
    BOOST_CHECK(!roster);
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
}

BOOST_AUTO_TEST_CASE(snapshot_lag_covers_signing_boundary)
{
    auto too_recent{BuildConfig(Schedule().sign_lag - 1)};
    BOOST_CHECK(!too_recent.IsValid());

    auto boundary{BuildConfig(Schedule().sign_lag)};
    BOOST_CHECK(boundary.IsValid());
}

BOOST_AUTO_TEST_CASE(null_snapshot_fails_before_modifier_derivation)
{
    constexpr uint32_t EPOCH{4};
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto roster{BuildTestRoster(
        NonNullHash(11), BuildConfig(), EPOCH, NonNullHash(12),
        CDeterministicMNList{}, {}, &error)};
    BOOST_CHECK(!roster);
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);
}

BOOST_AUTO_TEST_CASE(fewer_than_400_unsafe_cutoff_and_duplicate_keys_fail_closed)
{
    constexpr uint32_t EPOCH{4};
    const uint256 genesis{NonNullHash(11)};
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto too_small = Snapshot(2448, NonNullHash(12), QUORUM_SIZE - 1);
    const auto too_few_keys{KeyStates(
        QUORUM_SIZE - 1, EPOCH, /*snapshot_height=*/2448)};
    BOOST_CHECK(!BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(13), too_small,
        too_few_keys,
        &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);

    auto unsafe_config = BuildConfig();
    unsafe_config.registration_cutoff_blocks =
        unsafe_config.roster_snapshot_lag_blocks - 1;
    BOOST_CHECK(!unsafe_config.IsValid());
    BOOST_CHECK(!BuildTestRoster(
        genesis, unsafe_config, EPOCH, NonNullHash(15),
        Snapshot(2448, NonNullHash(14), QUORUM_SIZE), {}, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INVALID_SCHEDULE);

    auto epoch_boundary_config = BuildConfig(Schedule().epoch_blocks);
    BOOST_CHECK(epoch_boundary_config.IsValid());
    auto multi_epoch_lag_config =
        BuildConfig(Schedule().epoch_blocks + 1);
    BOOST_CHECK(!multi_epoch_lag_config.IsValid());

    const auto frozen_snapshot = Snapshot(2448, NonNullHash(16), QUORUM_SIZE);
    auto frozen_keys{KeyStates(QUORUM_SIZE, EPOCH, 2448)};
    const auto first = BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot,
        frozen_keys, nullptr);
    BOOST_REQUIRE(first);
    frozen_keys[1].frozen_child_roots[0].commitment.tree_id =
        frozen_keys[0].frozen_child_roots[0].commitment.tree_id;
    frozen_keys[1].global_key.child_key_commitment.tree_id =
        frozen_keys[0].global_key.child_key_commitment.tree_id;
    BOOST_REQUIRE(frozen_keys[1].IsStructurallyValid());
    BOOST_CHECK(!BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot,
        frozen_keys, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::DUPLICATE_CHILD_KEY);

    const auto oversized_snapshot{
        Snapshot(2448, NonNullHash(18), QUORUM_SIZE + 20)};
    auto oversized_keys{KeyStates(QUORUM_SIZE + 20, EPOCH, 2448)};
    const auto baseline{BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(19),
        oversized_snapshot, oversized_keys, &error)};
    BOOST_REQUIRE(baseline);
    std::vector<OperatorKeyState*> unselected;
    for (auto& state : oversized_keys) {
        if (!ContainsMember(*baseline, state.pro_tx_hash)) {
            unselected.push_back(&state);
        }
    }
    BOOST_REQUIRE_GE(unselected.size(), 2U);
    unselected[1]->frozen_child_roots[0].commitment.tree_id =
        unselected[0]->frozen_child_roots[0].commitment.tree_id;
    unselected[1]->global_key.child_key_commitment.tree_id =
        unselected[0]->global_key.child_key_commitment.tree_id;
    BOOST_REQUIRE(unselected[1]->IsStructurallyValid());
    const auto duplicate_below_cutoff{BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(19),
        oversized_snapshot, oversized_keys, &error)};
    BOOST_REQUIRE(duplicate_below_cutoff);
    BOOST_CHECK(duplicate_below_cutoff->descriptor == baseline->descriptor);

    frozen_keys = KeyStates(QUORUM_SIZE, EPOCH, 2448);
    frozen_keys[1] = frozen_keys[0];
    BOOST_CHECK(!BuildTestRoster(
        genesis, BuildConfig(), EPOCH, NonNullHash(17), frozen_snapshot,
        frozen_keys, &error));
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE, SNAPSHOT_LAG);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto a = BuildTestActiveRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_a.Tip(),
        lookup, &error);
    const auto b = BuildTestActiveRosters(
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE, SNAPSHOT_LAG);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    BOOST_CHECK(!BuildTestActiveRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_b.Tip(),
        wrong_fork, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);

    BOOST_CHECK(!BuildTestActiveRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT,
        chain_a.At(TARGET_HEIGHT - 1), lookup, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::MISSING_BRANCH_ANCESTOR);

    const QuorumSnapshotLookup unavailable = [](const CBlockIndex&) {
        return std::optional<QuorumSnapshotState>{QuorumSnapshotState{}};
    };
    BOOST_CHECK(!BuildTestActiveRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain_a.Tip(),
        unavailable, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::SNAPSHOT_MISMATCH);
}

BOOST_AUTO_TEST_CASE(recovery_retries_roll_over_the_pre_f_identity_universe)
{
    constexpr int32_t FIRST_TARGET{3465};
    constexpr int32_t SECOND_TARGET{4610};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'001)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain canonical(SECOND_TARGET, SECOND_TARGET + 1, 0);

    const auto source{RecoverySourceForChain(
        canonical.Tip(), SOURCE_EPOCH, 18'002)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);

    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        const uint32_t count{MEMBER_COUNT +
            static_cast<uint32_t>(index.nHeight != *source_snapshot_height)};
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), count);
        result.operator_key_states = index.nHeight == *source_snapshot_height
            ? SharedOperatorStates(KeyStates(
                  count, SOURCE_EPOCH, index.nHeight))
            : SharedOperatorStates(
                  RecoveryTargetKeyStates(count, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, config, lookup)};
    BOOST_REQUIRE(cache);
    const auto first_bundle{
        RecoveryBeaconBundleAtHeight(FIRST_TARGET, source)};
    const auto second_bundle{
        RecoveryBeaconBundleAtHeight(SECOND_TARGET, source)};
    const auto first{cache->GetVerifiedActive(
        FIRST_TARGET, canonical.Tip(), first_bundle, &error)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    const auto second{cache->GetVerifiedActive(
        SECOND_TARGET, canonical.Tip(), second_bundle, &error)};
    BOOST_REQUIRE(second);

    bool changed_membership{false};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            const auto& first_member{first->Rosters()[slot].members[member]};
            const auto& second_member{second->Rosters()[slot].members[member]};
            changed_membership |=
                first_member.pro_tx_hash != second_member.pro_tx_hash;
            BOOST_CHECK(first_member.pro_tx_hash !=
                        NonNullHash(10'000 + MEMBER_COUNT));
            BOOST_CHECK(second_member.pro_tx_hash !=
                        NonNullHash(10'000 + MEMBER_COUNT));
        }
    }
    BOOST_CHECK(changed_membership);

    auto changed_f{source};
    changed_f.normal_beacon.future_btc_hash = NonNullHash(18'003);
    const auto different_f_bundle{
        RecoveryBeaconBundleAtHeight(FIRST_TARGET, changed_f)};
    const auto different_f{cache->GetVerifiedActive(
        FIRST_TARGET, canonical.Tip(), different_f_bundle, &error)};
    BOOST_REQUIRE(different_f);
    bool changed_by_f{false};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            changed_by_f |= first->Rosters()[slot].members[member].pro_tx_hash !=
                different_f->Rosters()[slot].members[member].pro_tx_hash;
        }
    }
    BOOST_CHECK(changed_by_f);
}

BOOST_AUTO_TEST_CASE(
    recovery_sibling_cache_preserves_branch_bound_descriptors)
{
    constexpr uint32_t RECOVERY_EPOCH{19};
    constexpr int32_t TARGET_HEIGHT{6915};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'015)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    const BTCCScheduleConfig btcc{.candidate_origin = 2305};
    const auto canonical{CanonicalRosterRecoveryTargetHeight(
        config.schedule, btcc, RECOVERY_EPOCH)};
    const auto newest_base_height{
        EpochBaseHeight(config.schedule, RECOVERY_EPOCH)};
    BOOST_REQUIRE(canonical);
    BOOST_REQUIRE(newest_base_height);
    BOOST_REQUIRE_EQUAL(*canonical, TARGET_HEIGHT);
    BOOST_REQUIRE_EQUAL(TARGET_HEIGHT - *newest_base_height, 3);

    const int32_t signing_boundary_height{
        TARGET_HEIGHT - static_cast<int32_t>(config.schedule.sign_lag)};
    BOOST_REQUIRE_LT(signing_boundary_height, *newest_base_height);
    IndexChain first(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    IndexChain sibling(
        TARGET_HEIGHT, signing_boundary_height + 1, 18'016);
    BOOST_CHECK(first.At(signing_boundary_height).GetBlockHash() ==
                sibling.At(signing_boundary_height).GetBlockHash());
    BOOST_CHECK(first.At(*newest_base_height).GetBlockHash() !=
                sibling.At(*newest_base_height).GetBlockHash());

    const auto source{RecoverySourceForChain(
        first.Tip(), SOURCE_EPOCH, 18'017)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);
    const auto recovery_bundle{
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};

    std::optional<uint256> target_local_disabled;
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        if (target_local_disabled && index.nHeight == TARGET_HEIGHT &&
            index.GetBlockHash() == sibling.Tip().GetBlockHash()) {
            std::vector<CDeterministicMNCPtr> members;
            members.reserve(MEMBER_COUNT - 1);
            for (uint32_t tag{0}; tag < MEMBER_COUNT; ++tag) {
                auto member{Member(tag)};
                if (member->proTxHash != *target_local_disabled) {
                    members.push_back(std::move(member));
                }
            }
            result.deterministic_mns = SnapshotFromMembers(
                index.nHeight, index.GetBlockHash(), members);
        } else {
            result.deterministic_mns = Snapshot(
                index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        }
        result.operator_key_states = index.nHeight == *source_snapshot_height
            ? SharedOperatorStates(KeyStates(
                  MEMBER_COUNT, SOURCE_EPOCH, index.nHeight))
            : SharedOperatorStates(
                  RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto first_uncached{BuildActiveFrozenQuorumRosters(
        genesis, config, TARGET_HEIGHT, first.Tip(), recovery_bundle,
        lookup, &error)};
    BOOST_REQUIRE_MESSAGE(
        first_uncached, "quorum build error=" << static_cast<int>(error));
    target_local_disabled =
        first_uncached->front().members.front().pro_tx_hash;
    const auto sibling_uncached{BuildActiveFrozenQuorumRosters(
        genesis, config, TARGET_HEIGHT, sibling.Tip(), recovery_bundle,
        lookup, &error)};
    BOOST_REQUIRE_MESSAGE(
        sibling_uncached, "quorum build error=" << static_cast<int>(error));

    const auto check_siblings = [&](const FrozenQuorumRosters& lhs,
                                    const FrozenQuorumRosters& rhs) {
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            BOOST_CHECK(lhs[slot].members == rhs[slot].members);
            auto normalized{rhs[slot].descriptor};
            if (slot == ACTIVE_QUORUMS - 1) {
                BOOST_CHECK(lhs[slot].descriptor.base_hash !=
                            normalized.base_hash);
                normalized.base_hash = lhs[slot].descriptor.base_hash;
            }
            BOOST_CHECK(lhs[slot].descriptor == normalized);
        }
    };
    check_siblings(*first_uncached, *sibling_uncached);

    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, config, lookup)};
    BOOST_REQUIRE(cache);
    const auto first_cached{cache->GetVerifiedActive(
        TARGET_HEIGHT, first.Tip(), recovery_bundle, &error)};
    const auto sibling_cached{cache->GetVerifiedActive(
        TARGET_HEIGHT, sibling.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(first_cached);
    BOOST_REQUIRE(sibling_cached);
    BOOST_CHECK(first_cached != sibling_cached);
    BOOST_CHECK(first_cached->Rosters() == *first_uncached);
    BOOST_CHECK(sibling_cached->Rosters() == *sibling_uncached);
    check_siblings(first_cached->Rosters(), sibling_cached->Rosters());
}

BOOST_AUTO_TEST_CASE(recovery_capsule_matches_raw_selection_across_groups)
{
    constexpr int32_t FIRST_TARGET{3465};
    constexpr int32_t SECOND_TARGET{4610};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'020)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain canonical(SECOND_TARGET, SECOND_TARGET + 1, 0);
    const auto source{RecoverySourceForChain(
        canonical.Tip(), SOURCE_EPOCH, 18'021)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);

    const QuorumSnapshotLookup raw_lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states =
            index.nHeight == *source_snapshot_height
            ? SharedOperatorStates(KeyStates(
                  MEMBER_COUNT, SOURCE_EPOCH, index.nHeight))
            : SharedOperatorStates(RecoveryTargetKeyStates(
                  MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto capsule{BuildRecoveryUniverseCapsule(
        genesis, config, source, canonical.Tip(), raw_lookup, &error)};
    BOOST_REQUIRE(capsule);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(capsule->Members().size(), MEMBER_COUNT);

    const auto encoded{capsule->Encode()};
    const auto decoded{RecoveryUniverseCapsule::DecodeTrustedPersistence(
        encoded, &error)};
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(*decoded == *capsule);
    const auto restarted_capsule{
        std::make_shared<const RecoveryUniverseCapsule>(*decoded)};

    std::atomic<unsigned> pruned_source_reads{0};
    const QuorumSnapshotLookup pruned_lookup = [&](const CBlockIndex& index) {
        if (index.nHeight == *source_snapshot_height) {
            ++pruned_source_reads;
            return std::optional<QuorumSnapshotState>{};
        }
        return raw_lookup(index);
    };
    const RecoveryUniverseLookup capsule_lookup =
        [restarted_capsule](const uint256& source_id) {
            return source_id == restarted_capsule->SourceId()
                ? restarted_capsule
                : RecoveryUniverseCapsulePtr{};
        };
    const auto raw_cache{FrozenQuorumRosterCache::Create(
        genesis, config, raw_lookup)};
    const auto capsule_cache{FrozenQuorumRosterCache::Create(
        genesis, config, pruned_lookup, true, capsule_lookup)};
    BOOST_REQUIRE(raw_cache);
    BOOST_REQUIRE(capsule_cache);
    const auto persisted{capsule_cache->GetOrCaptureRecoveryUniverse(
        source, canonical.Tip(), &error)};
    BOOST_REQUIRE(persisted);
    BOOST_CHECK(*persisted == *restarted_capsule);
    BOOST_CHECK_EQUAL(pruned_source_reads.load(), 0U);

    for (const int32_t target : {FIRST_TARGET, SECOND_TARGET}) {
        const auto bundle{RecoveryBeaconBundleAtHeight(target, source)};
        const auto raw{raw_cache->GetVerifiedActive(
            target, canonical.Tip(), bundle, &error)};
        BOOST_REQUIRE(raw);
        const auto from_capsule{capsule_cache->GetVerifiedActive(
            target, canonical.Tip(), bundle, &error)};
        BOOST_REQUIRE(from_capsule);
        BOOST_CHECK(raw->Rosters() == from_capsule->Rosters());
    }
    BOOST_CHECK_EQUAL(pruned_source_reads.load(), 0U);
    const auto first_group{raw_cache->GetVerifiedActive(
        FIRST_TARGET, canonical.Tip(),
        RecoveryBeaconBundleAtHeight(FIRST_TARGET, source), &error)};
    const auto second_group{raw_cache->GetVerifiedActive(
        SECOND_TARGET, canonical.Tip(),
        RecoveryBeaconBundleAtHeight(SECOND_TARGET, source), &error)};
    const auto restarted_first_group{capsule_cache->GetVerifiedActive(
        FIRST_TARGET, canonical.Tip(),
        RecoveryBeaconBundleAtHeight(FIRST_TARGET, source), &error)};
    const auto restarted_second_group{capsule_cache->GetVerifiedActive(
        SECOND_TARGET, canonical.Tip(),
        RecoveryBeaconBundleAtHeight(SECOND_TARGET, source), &error)};
    BOOST_REQUIRE(first_group);
    BOOST_REQUIRE(second_group);
    BOOST_REQUIRE(restarted_first_group);
    BOOST_REQUIRE(restarted_second_group);
    BOOST_CHECK(first_group->Rosters() != second_group->Rosters());
    BOOST_CHECK(restarted_first_group->Rosters() !=
                restarted_second_group->Rosters());
    BOOST_CHECK(first_group->Rosters() ==
                restarted_first_group->Rosters());
    BOOST_CHECK(second_group->Rosters() ==
                restarted_second_group->Rosters());
    BOOST_CHECK_EQUAL(pruned_source_reads.load(), 0U);
}

BOOST_AUTO_TEST_CASE(recovery_capsule_decode_is_strict_and_bounded)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 2};
    const uint256 genesis{NonNullHash(18'030)};
    const auto config{BuildConfig()};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'031)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH,
        config.roster_snapshot_lag_blocks)};
    BOOST_REQUIRE(source_snapshot_height);
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states = SharedOperatorStates(KeyStates(
            MEMBER_COUNT, SOURCE_EPOCH, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto capsule{BuildRecoveryUniverseCapsule(
        genesis, config, source, chain.Tip(), lookup, &error)};
    BOOST_REQUIRE(capsule);

    auto check_rejected = [&](std::vector<RecoveryUniverseMember> members) {
        const uint256 members_hash{GetRecoveryUniverseMembersHash(
            genesis, members)};
        const uint256 capsule_id{GetRecoveryUniverseCapsuleId(
            genesis, source, *source_snapshot_height,
            chain.At(*source_snapshot_height).GetBlockHash(), members_hash,
            members.size())};
        auto bytes{EncodeRecoveryUniverseUnchecked(
            RECOVERY_UNIVERSE_CAPSULE_VERSION, genesis, source,
            *source_snapshot_height,
            chain.At(*source_snapshot_height).GetBlockHash(), members,
            static_cast<uint32_t>(members.size()), members_hash,
            capsule_id)};
        if (members.size() < QUORUM_SIZE) {
            bytes.resize(RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE);
        }
        BOOST_CHECK(!RecoveryUniverseCapsule::DecodeTrustedPersistence(
            bytes, &error));
        BOOST_CHECK(error == QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
    };

    std::vector<RecoveryUniverseMember> duplicate_identity{
        capsule->Members().begin(), capsule->Members().end()};
    duplicate_identity[1].pro_tx_hash = duplicate_identity[0].pro_tx_hash;
    check_rejected(std::move(duplicate_identity));

    std::vector<RecoveryUniverseMember> duplicate_collateral{
        capsule->Members().begin(), capsule->Members().end()};
    duplicate_collateral[1].collateral_outpoint =
        duplicate_collateral[0].collateral_outpoint;
    check_rejected(std::move(duplicate_collateral));

    std::vector<RecoveryUniverseMember> too_small{
        capsule->Members().begin(),
        capsule->Members().begin() + QUORUM_SIZE - 1};
    check_rejected(std::move(too_small));

    auto oversized_header{EncodeRecoveryUniverseUnchecked(
        RECOVERY_UNIVERSE_CAPSULE_VERSION, genesis, source,
        *source_snapshot_height,
        chain.At(*source_snapshot_height).GetBlockHash(), {},
        static_cast<uint32_t>(RECOVERY_UNIVERSE_MAX_MEMBERS + 1),
        NonNullHash(18'032), NonNullHash(18'033))};
    oversized_header.resize(RecoveryUniverseCapsule::MIN_SERIALIZED_SIZE);
    BOOST_CHECK(!RecoveryUniverseCapsule::DecodeTrustedPersistence(
        oversized_header, &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_RECOVERY_UNIVERSE);

    auto corrupted{capsule->Encode()};
    corrupted.back() ^= 1;
    BOOST_CHECK(!RecoveryUniverseCapsule::DecodeTrustedPersistence(
        corrupted, &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
}

BOOST_AUTO_TEST_CASE(recovery_capsule_source_mismatch_fails_closed)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 10};
    const uint256 genesis{NonNullHash(18'040)};
    const auto config{BuildConfig()};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'041)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH,
        config.roster_snapshot_lag_blocks)};
    BOOST_REQUIRE(source_snapshot_height);
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states = SharedOperatorStates(
            index.nHeight == *source_snapshot_height
                ? KeyStates(MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                : RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto capsule{BuildRecoveryUniverseCapsule(
        genesis, config, source, chain.Tip(), lookup, &error)};
    BOOST_REQUIRE(capsule);

    auto different_source{source};
    different_source.normal_beacon.future_btc_hash = NonNullHash(18'042);
    BOOST_REQUIRE(different_source.IsStructurallyValid());
    BOOST_CHECK(capsule->SourceId() ==
                GetRecoveryUniverseSourceId(genesis, source));
    BOOST_CHECK(capsule->SourceId() != GetRecoveryUniverseSourceId(
                    genesis, different_source));
    BOOST_CHECK(capsule->SourceId() != GetRecoveryUniverseSourceId(
                    NonNullHash(18'043), source));
    BOOST_CHECK(!capsule->Matches(
        genesis, different_source,
        chain.At(*source_snapshot_height)));

    std::atomic<unsigned> raw_source_reads{0};
    const QuorumSnapshotLookup no_source_replay =
        [&](const CBlockIndex& index) {
            if (index.nHeight == *source_snapshot_height) {
                ++raw_source_reads;
                return std::optional<QuorumSnapshotState>{};
            }
            return lookup(index);
    };
    const auto mismatched_capture_cache{FrozenQuorumRosterCache::Create(
        genesis, config, no_source_replay, true,
        [capsule](const uint256&) { return capsule; })};
    BOOST_REQUIRE(mismatched_capture_cache);
    BOOST_CHECK(!mismatched_capture_cache->GetOrCaptureRecoveryUniverse(
        different_source, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
    BOOST_CHECK_EQUAL(raw_source_reads.load(), 0U);

    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, config, no_source_replay, true,
        [capsule](const uint256&) {
            return capsule;
        })};
    BOOST_REQUIRE(cache);
    BOOST_CHECK(!cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(),
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, different_source),
        &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_RECOVERY_UNIVERSE);
    BOOST_CHECK_EQUAL(raw_source_reads.load(), 0U);

    const auto throwing_cache{FrozenQuorumRosterCache::Create(
        genesis, config, no_source_replay, true,
        [](const uint256&) -> RecoveryUniverseCapsulePtr {
            throw std::runtime_error("local capsule DB unavailable");
        })};
    BOOST_REQUIRE(throwing_cache);
    BOOST_CHECK(!throwing_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(),
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source), &error));
    BOOST_CHECK(error ==
                QuorumBuildError::RECOVERY_UNIVERSE_LOOKUP_FAILED);
    BOOST_CHECK_EQUAL(raw_source_reads.load(), 0U);
}

BOOST_AUTO_TEST_CASE(recovery_excludes_never_registered_source_identity)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'050)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'051)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);
    const auto recovery_bundle{
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};

    const auto make_lookup = [&](std::optional<uint256> rootless_at_source) {
        return QuorumSnapshotLookup{
            [&, rootless_at_source](const CBlockIndex& index) {
                QuorumSnapshotState result;
                result.deterministic_mns = Snapshot(
                    index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
                auto states{index.nHeight == *source_snapshot_height
                    ? KeyStates(
                          MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                    : RecoveryTargetKeyStates(
                          MEMBER_COUNT, index.nHeight)};
                if (index.nHeight == *source_snapshot_height &&
                    rootless_at_source) {
                    const auto found{std::find_if(
                        states.begin(), states.end(),
                        [&](const OperatorKeyState& state) {
                            return state.pro_tx_hash == *rootless_at_source;
                        })};
                    BOOST_REQUIRE(found != states.end());
                    const auto view{DeriveOperatorKeyScheduleView(
                        config.schedule, index.nHeight,
                        config.registration_cutoff_blocks,
                        config.future_horizon_epochs)};
                    BOOST_REQUIRE(view);
                    *found = OperatorKeyState::ForOperator(
                        *rootless_at_source);
                    found->schedule_initialized = 1;
                    found->schedule =
                        OperatorKeyScheduleState::FromView(*view);
                    BOOST_REQUIRE(found->IsStructurallyValid());
                }
                result.operator_key_states = SharedOperatorStates(
                    std::move(states));
                return std::optional<QuorumSnapshotState>{
                    std::move(result)};
            }};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto baseline_cache{FrozenQuorumRosterCache::Create(
        genesis, config, make_lookup(std::nullopt))};
    BOOST_REQUIRE(baseline_cache);
    const auto baseline{baseline_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(baseline);
    const uint256 high_score_identity{
        baseline->Rosters().front().members.front().pro_tx_hash};

    const auto filtered_cache{FrozenQuorumRosterCache::Create(
        genesis, config, make_lookup(high_score_identity))};
    BOOST_REQUIRE(filtered_cache);
    const auto filtered{filtered_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE_MESSAGE(
        filtered, "quorum build error=" << static_cast<int>(error));
    for (const auto& roster : filtered->Rosters()) {
        BOOST_CHECK(!ContainsMember(roster, high_score_identity));
        BOOST_CHECK_EQUAL(roster.descriptor.valid_count, QUORUM_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(recovery_retains_revoked_source_identity_for_later_repair)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'060)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'061)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);
    const auto recovery_bundle{
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};

    const auto baseline_lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states = SharedOperatorStates(
            index.nHeight == *source_snapshot_height
                ? KeyStates(
                      MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                : RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto baseline_cache{FrozenQuorumRosterCache::Create(
        genesis, config, baseline_lookup)};
    BOOST_REQUIRE(baseline_cache);
    const auto baseline{baseline_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(baseline);
    const uint256 selected_identity{
        baseline->Rosters().front().members.front().pro_tx_hash};

    const auto make_lookup = [&](bool repaired_after_source) {
        return QuorumSnapshotLookup{
            [&, repaired_after_source](const CBlockIndex& index) {
                QuorumSnapshotState result;
                result.deterministic_mns = Snapshot(
                    index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
                const bool is_source{
                    index.nHeight == *source_snapshot_height};
                auto states{is_source
                    ? KeyStates(
                          MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                    : RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight)};
                if (is_source || !repaired_after_source) {
                    const auto found{std::find_if(
                        states.begin(), states.end(),
                        [&](const OperatorKeyState& state) {
                            return state.pro_tx_hash == selected_identity;
                        })};
                    BOOST_REQUIRE(found != states.end());
                    found->global_key_active = 0;
                    found->revoked_height =
                        static_cast<uint32_t>(index.nHeight);
                    found->frozen_child_roots.clear();
                    BOOST_REQUIRE(found->has_global_key != 0);
                    BOOST_REQUIRE(found->IsStructurallyValid());
                }
                result.operator_key_states = SharedOperatorStates(
                    std::move(states));
                return std::optional<QuorumSnapshotState>{
                    std::move(result)};
            }};
    };

    const auto unrepaired_cache{FrozenQuorumRosterCache::Create(
        genesis, config, make_lookup(/*repaired_after_source=*/false))};
    BOOST_REQUIRE(unrepaired_cache);
    const auto unrepaired{unrepaired_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(unrepaired);
    const auto unrepaired_slot{
        FindMember(unrepaired->Rosters().front(), selected_identity)};
    BOOST_REQUIRE_LT(unrepaired_slot, QUORUM_SIZE);
    BOOST_CHECK(!unrepaired->Rosters().front()
                     .members[unrepaired_slot].eligible);

    const auto repaired_cache{FrozenQuorumRosterCache::Create(
        genesis, config, make_lookup(/*repaired_after_source=*/true))};
    BOOST_REQUIRE(repaired_cache);
    const auto repaired{repaired_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(repaired);
    const auto repaired_slot{
        FindMember(repaired->Rosters().front(), selected_identity)};
    BOOST_REQUIRE_LT(repaired_slot, QUORUM_SIZE);
    BOOST_CHECK(repaired->Rosters().front().members[repaired_slot].eligible);
    BOOST_CHECK_EQUAL(repaired_slot, unrepaired_slot);
}

BOOST_AUTO_TEST_CASE(recovery_cutoff_pose_state_does_not_disable_revived_target)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 30};
    const uint256 genesis{NonNullHash(18'080)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'081)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    const auto key_cutoff_height{RegistrationCutoffHeight(
        config.schedule, /*epoch=*/4, config.registration_cutoff_blocks)};
    BOOST_REQUIRE(source_snapshot_height);
    BOOST_REQUIRE(key_cutoff_height);
    const auto recovery_bundle{
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};

    const QuorumSnapshotLookup baseline_lookup = [&](const CBlockIndex& index) {
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states = SharedOperatorStates(
            index.nHeight == *source_snapshot_height
                ? KeyStates(
                      MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                : RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto baseline_cache{FrozenQuorumRosterCache::Create(
        genesis, config, baseline_lookup)};
    BOOST_REQUIRE(baseline_cache);
    const auto baseline{baseline_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(baseline);
    const uint256 revived_identity{
        baseline->Rosters().front().members.front().pro_tx_hash};

    const QuorumSnapshotLookup revived_lookup = [&](const CBlockIndex& index) {
        std::vector<CDeterministicMNCPtr> members;
        members.reserve(MEMBER_COUNT);
        for (uint32_t tag{0}; tag < MEMBER_COUNT; ++tag) {
            const bool banned_at_cutoff{
                index.nHeight == *key_cutoff_height &&
                NonNullHash(10'000 + tag) == revived_identity};
            members.push_back(Member(tag, banned_at_cutoff));
        }
        QuorumSnapshotState result;
        result.deterministic_mns = SnapshotFromMembers(
            index.nHeight, index.GetBlockHash(), members);
        result.operator_key_states = SharedOperatorStates(
            index.nHeight == *source_snapshot_height
                ? KeyStates(
                      MEMBER_COUNT, SOURCE_EPOCH, index.nHeight)
                : RecoveryTargetKeyStates(MEMBER_COUNT, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto revived_cache{FrozenQuorumRosterCache::Create(
        genesis, config, revived_lookup)};
    BOOST_REQUIRE(revived_cache);
    const auto revived{revived_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE_MESSAGE(
        revived, "quorum build error=" << static_cast<int>(error));
    const auto revived_slot{
        FindMember(revived->Rosters().front(), revived_identity)};
    BOOST_REQUIRE_LT(revived_slot, QUORUM_SIZE);
    BOOST_CHECK_EQUAL(revived_slot, 0U);
    BOOST_CHECK(revived->Rosters().front().members[revived_slot].eligible);
    BOOST_CHECK(revived->Rosters().front().members[revived_slot].child_root);
}

BOOST_AUTO_TEST_CASE(
    recovery_keys_freeze_at_cutoff_and_signing_boundary_only_disables)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t SOURCE_MEMBERS{QUORUM_SIZE + 30};
    constexpr uint32_t TARGET_MEMBERS{SOURCE_MEMBERS + 1};
    const uint256 genesis{NonNullHash(18'100)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    const int32_t signing_boundary_height{
        TARGET_HEIGHT - static_cast<int32_t>(config.schedule.sign_lag)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);

    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'101)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        config.schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    const auto key_cutoff_height{RegistrationCutoffHeight(
        config.schedule, /*epoch=*/4, config.registration_cutoff_blocks)};
    BOOST_REQUIRE(source_snapshot_height);
    BOOST_REQUIRE(key_cutoff_height);
    const auto recovery_bundle{
        RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};

    const QuorumSnapshotLookup baseline_lookup = [&](const CBlockIndex& index) {
        const uint32_t count{index.nHeight == *source_snapshot_height
            ? SOURCE_MEMBERS
            : TARGET_MEMBERS};
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), count);
        result.operator_key_states = index.nHeight == *source_snapshot_height
            ? SharedOperatorStates(KeyStates(
                  count, SOURCE_EPOCH, index.nHeight))
            : SharedOperatorStates(
                  RecoveryTargetKeyStates(count, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    QuorumBuildError error{QuorumBuildError::NONE};
    const auto baseline_cache{FrozenQuorumRosterCache::Create(
        genesis, config, baseline_lookup)};
    BOOST_REQUIRE(baseline_cache);
    const auto baseline{baseline_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE_MESSAGE(
        baseline, "quorum build error=" << static_cast<int>(error));
    for (const auto& roster : baseline->Rosters()) {
        BOOST_CHECK_EQUAL(roster.descriptor.valid_count, QUORUM_SIZE);
    }
    const uint256 post_source_identity{
        NonNullHash(10'000 + SOURCE_MEMBERS)};
    for (const auto& roster : baseline->Rosters()) {
        BOOST_CHECK(!ContainsMember(roster, post_source_identity));
    }

    const uint256 refreshed_identity{
        baseline->Rosters()[0].members[0].pro_tx_hash};
    const uint256 missing_at_cutoff{
        baseline->Rosters()[0].members[1].pro_tx_hash};
    const uint256 disabled_identity{
        baseline->Rosters()[0].members[2].pro_tx_hash};
    const uint256 changed_after_cutoff_identity{
        baseline->Rosters()[0].members[3].pro_tx_hash};

    const auto refresh_root = [&](std::vector<OperatorKeyState>& states,
                                  int32_t height) {
        const auto it{std::find_if(
            states.begin(), states.end(), [&](const OperatorKeyState& state) {
                return state.pro_tx_hash == refreshed_identity;
            })};
        BOOST_REQUIRE(it != states.end());
        it->global_key.key_version = 2;
        it->global_key.public_key[0] ^= 0x3f;
        it->global_key.activated_height = static_cast<uint32_t>(height);
        it->global_key.child_key_commitment.generation = 2;
        it->global_key.child_key_commitment.first_epoch = 4;
        it->global_key.child_key_commitment.tree_id = NonNullHash(181'001);
        it->global_key.child_key_commitment.root = NonNullHash(181'002);
        it->frozen_child_roots.clear();
        for (uint32_t epoch{it->schedule.first_retained_frozen_epoch};
             epoch < it->schedule.first_mutable_epoch; ++epoch) {
            if (it->global_key.child_key_commitment.CoversEpoch(epoch)) {
                it->frozen_child_roots.push_back(FrozenChildRootRecord{
                    it->pro_tx_hash, it->global_key.key_version, epoch,
                    it->global_key.child_key_commitment});
            }
        }
        BOOST_REQUIRE(it->IsStructurallyValid());
    };
    const QuorumSnapshotLookup refreshed_lookup =
        [&](const CBlockIndex& index) {
            const bool is_source{
                index.nHeight == *source_snapshot_height};
            const uint32_t count{is_source
                ? SOURCE_MEMBERS
                : TARGET_MEMBERS};
            QuorumSnapshotState result;
            result.deterministic_mns = Snapshot(
                index.nHeight, index.GetBlockHash(), count);
            auto states{is_source
                ? KeyStates(
                      count, SOURCE_EPOCH, index.nHeight)
                : RecoveryTargetKeyStates(count, index.nHeight)};
            if (!is_source) refresh_root(states, index.nHeight);
            result.operator_key_states = SharedOperatorStates(
                std::move(states));
            return std::optional<QuorumSnapshotState>{std::move(result)};
        };
    const auto refreshed_cache{FrozenQuorumRosterCache::Create(
        genesis, config, refreshed_lookup)};
    BOOST_REQUIRE(refreshed_cache);
    const auto refreshed{refreshed_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(refreshed);
    const auto refreshed_slot{FindMember(
        refreshed->Rosters()[0], refreshed_identity)};
    BOOST_REQUIRE_LT(refreshed_slot, QUORUM_SIZE);
    BOOST_REQUIRE(refreshed->Rosters()[0].members[refreshed_slot].child_root);
    BOOST_CHECK_EQUAL(
        refreshed->Rosters()[0].members[refreshed_slot]
            .child_root->global_key_version,
        2U);

    const QuorumSnapshotLookup degraded_lookup =
        [&](const CBlockIndex& index) {
            const bool is_source{index.nHeight == *source_snapshot_height};
            QuorumSnapshotState result;
            std::vector<CDeterministicMNCPtr> members;
            const uint32_t count{is_source ? SOURCE_MEMBERS : TARGET_MEMBERS};
            members.reserve(count);
            for (uint32_t tag{0}; tag < count; ++tag) {
                auto member{Member(tag)};
                if (index.nHeight != signing_boundary_height ||
                    member->proTxHash != disabled_identity) {
                    members.push_back(std::move(member));
                }
            }
            result.deterministic_mns = SnapshotFromMembers(
                index.nHeight, index.GetBlockHash(), members);
            auto states{is_source
                                  ? KeyStates(
                                        count, SOURCE_EPOCH,
                                        index.nHeight)
                                  : RecoveryTargetKeyStates(
                                        count, index.nHeight)};
            if (index.nHeight == *key_cutoff_height) {
                states.erase(std::remove_if(
                    states.begin(), states.end(),
                    [&](const OperatorKeyState& state) {
                        return state.pro_tx_hash == missing_at_cutoff;
                    }), states.end());
            }
            if (index.nHeight == signing_boundary_height) {
                const auto state{std::find_if(
                    states.begin(), states.end(),
                    [&](const OperatorKeyState& candidate) {
                        return candidate.pro_tx_hash ==
                            changed_after_cutoff_identity;
                    })};
                BOOST_REQUIRE(state != states.end());
                const auto root{std::find_if(
                    state->frozen_child_roots.begin(),
                    state->frozen_child_roots.end(),
                    [](const FrozenChildRootRecord& candidate) {
                        return candidate.epoch == 4;
                    })};
                BOOST_REQUIRE(root != state->frozen_child_roots.end());
                root->commitment.root = NonNullHash(181'003);
                BOOST_REQUIRE(state->IsStructurallyValid());
            }
            result.operator_key_states = SharedOperatorStates(
                std::move(states));
            return std::optional<QuorumSnapshotState>{std::move(result)};
        };
    const auto degraded_cache{FrozenQuorumRosterCache::Create(
        genesis, config, degraded_lookup)};
    BOOST_REQUIRE(degraded_cache);
    const auto degraded{degraded_cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), recovery_bundle, &error)};
    BOOST_REQUIRE(degraded);

    bool observed_cutoff_hole{false};
    bool observed_disabled_slot{false};
    bool observed_changed_root{false};
    for (std::size_t roster_slot{0};
         roster_slot < ACTIVE_QUORUMS; ++roster_slot) {
        for (std::size_t member_index{0};
             member_index < QUORUM_SIZE; ++member_index) {
            const auto& before{
                baseline->Rosters()[roster_slot].members[member_index]};
            const auto& after{
                degraded->Rosters()[roster_slot].members[member_index]};
            BOOST_CHECK(after.pro_tx_hash == before.pro_tx_hash);
            if (after.pro_tx_hash == missing_at_cutoff) {
                observed_cutoff_hole = true;
                BOOST_REQUIRE(before.eligible);
                BOOST_CHECK(!after.eligible);
                BOOST_CHECK(!after.child_root);
            }
            if (after.pro_tx_hash == disabled_identity) {
                observed_disabled_slot = true;
                BOOST_REQUIRE(before.eligible);
                BOOST_CHECK(!after.eligible);
                BOOST_CHECK(after.child_root.has_value());
            }
            if (roster_slot == 0 &&
                after.pro_tx_hash == changed_after_cutoff_identity) {
                observed_changed_root = true;
                BOOST_REQUIRE(before.eligible);
                BOOST_CHECK(!after.eligible);
                BOOST_REQUIRE(after.child_root);
                BOOST_CHECK(after.child_root == before.child_root);
            }
        }
    }
    BOOST_CHECK(observed_cutoff_hole);
    BOOST_CHECK(observed_disabled_slot);
    BOOST_CHECK(observed_changed_root);
}

BOOST_AUTO_TEST_CASE(recovery_requires_three_usable_retained_rosters)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{3};
    constexpr uint32_t SNAPSHOT_LAG{144};
    const uint256 genesis{NonNullHash(18'200)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'201)};
    const auto source_snapshot_height{RegistrationCutoffHeight(
        BuildConfig(SNAPSHOT_LAG).schedule, SOURCE_EPOCH, SNAPSHOT_LAG)};
    BOOST_REQUIRE(source_snapshot_height);
    const auto make_lookup = [&](uint32_t usable_members) {
        return QuorumSnapshotLookup{
            [&, usable_members](const CBlockIndex& index) {
                QuorumSnapshotState result;
                result.deterministic_mns = Snapshot(
                    index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
                result.operator_key_states =
                    index.nHeight == *source_snapshot_height
                    ? SharedOperatorStates(KeyStates(
                          QUORUM_SIZE, SOURCE_EPOCH, index.nHeight))
                    : SharedOperatorStates(RecoveryTargetKeyStates(
                          usable_members, index.nHeight));
                return std::optional<QuorumSnapshotState>{std::move(result)};
            }};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto bundle{RecoveryBeaconBundleAtHeight(TARGET_HEIGHT, source)};
    const auto exact_threshold{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG),
        make_lookup(QUORUM_MIN_VALID))};
    BOOST_REQUIRE(exact_threshold);
    const auto accepted{exact_threshold->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), bundle, &error)};
    BOOST_REQUIRE(accepted);
    for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK_EQUAL(
            accepted->Rosters()[slot].descriptor.valid_count,
            QUORUM_MIN_VALID);
    }

    const auto below_threshold{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG),
        make_lookup(QUORUM_MIN_VALID - 1))};
    BOOST_REQUIRE(below_threshold);
    BOOST_CHECK(!below_threshold->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), bundle, &error));
    BOOST_CHECK(error == QuorumBuildError::CHILD_KEY_NOT_FROZEN);
}

BOOST_AUTO_TEST_CASE(future_recovery_source_requires_400_frozen_roots)
{
    constexpr int32_t TARGET_HEIGHT{3605};
    constexpr int32_t SOURCE_ANCHOR_HEIGHT{3601};
    constexpr uint32_t SOURCE_EPOCH{8};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 20};
    const uint256 genesis{NonNullHash(18'250)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);

    RecoveryRosterAuthoritySource source;
    source.normal_beacon = ReadyBeaconSeed(SOURCE_EPOCH, 18'251);
    source.normal_beacon.anchor_cursor.sys_height = SOURCE_ANCHOR_HEIGHT;
    source.normal_beacon.anchor_cursor.sys_hash =
        chain.At(SOURCE_ANCHOR_HEIGHT).GetBlockHash();
    BOOST_REQUIRE(source.IsStructurallyValid());
    const auto source_snapshot_height{RegistrationCutoffHeight(
        BuildConfig().schedule, SOURCE_EPOCH,
        BuildConfig().roster_snapshot_lag_blocks)};
    BOOST_REQUIRE(source_snapshot_height);
    BOOST_REQUIRE_LT(*source_snapshot_height, SOURCE_ANCHOR_HEIGHT);

    auto bundle{BeaconBundleAtHeight(TARGET_HEIGHT)};
    bundle.recovery_authority_source = source;
    BOOST_REQUIRE(bundle.IsStructurallyValid());
    const auto make_lookup = [&](uint32_t source_roots) {
        return QuorumSnapshotLookup{
            [&, source_roots](const CBlockIndex& index) {
                constexpr uint32_t SNAPSHOT_LAG{144};
                const auto epoch{EpochForHeight(
                    Schedule(), index.nHeight +
                                    static_cast<int32_t>(SNAPSHOT_LAG))};
                if (!epoch) return std::optional<QuorumSnapshotState>{};
                QuorumSnapshotState result;
                result.deterministic_mns = Snapshot(
                    index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
                const uint32_t roots{index.nHeight == *source_snapshot_height
                    ? source_roots
                    : MEMBER_COUNT};
                result.operator_key_states = SharedOperatorStates(
                    KeyStates(roots, *epoch, index.nHeight));
                return std::optional<QuorumSnapshotState>{std::move(result)};
            }};
    };

    QuorumBuildError error{QuorumBuildError::NONE};
    const auto insufficient{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), make_lookup(QUORUM_SIZE - 1))};
    BOOST_REQUIRE(insufficient);
    const auto insufficient_evaluation{
        insufficient->EvaluateNormalRecoverySource(
            source, chain.Tip(), &error)};
    BOOST_REQUIRE(insufficient_evaluation);
    BOOST_CHECK(!*insufficient_evaluation);
    BOOST_CHECK_EQUAL(error,
                      QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);
    BOOST_CHECK(!insufficient->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), bundle, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::INSUFFICIENT_ELIGIBLE_MEMBERS);

    const auto sufficient{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), make_lookup(QUORUM_SIZE))};
    BOOST_REQUIRE(sufficient);
    const auto sufficient_evaluation{
        sufficient->EvaluateNormalRecoverySource(
            source, chain.Tip(), &error)};
    BOOST_REQUIRE(sufficient_evaluation);
    BOOST_CHECK(*sufficient_evaluation);
    BOOST_CHECK_EQUAL(error, QuorumBuildError::NONE);
    BOOST_REQUIRE(sufficient->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), bundle, &error));
    BOOST_CHECK_EQUAL(error, QuorumBuildError::NONE);
}

BOOST_AUTO_TEST_CASE(normal_bundle_carries_only_the_recovery_source)
{
    constexpr int32_t TARGET_HEIGHT{3465};
    constexpr uint32_t SOURCE_EPOCH{6};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint32_t MEMBER_COUNT{QUORUM_SIZE + 20};
    const uint256 genesis{NonNullHash(18'300)};
    const auto config{BuildConfig(SNAPSHOT_LAG)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    const auto source{RecoverySourceForChain(
        chain.Tip(), SOURCE_EPOCH, 18'301)};

    QuorumBuildError error{QuorumBuildError::NONE};

    auto bundle{BeaconBundleAtHeight(TARGET_HEIGHT)};
    bundle.recovery_authority_source = source;
    BOOST_REQUIRE(bundle.IsStructurallyValid());
    const QuorumSnapshotLookup normal_lookup = [&](const CBlockIndex& index) {
        const auto epoch{EpochForHeight(
            Schedule(), index.nHeight +
                            static_cast<int32_t>(SNAPSHOT_LAG))};
        BOOST_REQUIRE(epoch);
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), MEMBER_COUNT);
        result.operator_key_states = SharedOperatorStates(
            KeyStates(MEMBER_COUNT, *epoch, index.nHeight));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, config, normal_lookup)};
    BOOST_REQUIRE(cache);
    const auto verified{cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), bundle, &error)};
    BOOST_REQUIRE(verified);
    BOOST_CHECK(error == QuorumBuildError::NONE);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_reuses_exact_branch_contexts)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t SECOND_TARGET{2310};
    const uint256 genesis{NonNullHash(20)};
    IndexChain canonical(SECOND_TARGET, SECOND_TARGET + 1, 0);
    IndexChain fork_after_base(SECOND_TARGET, 2306, 0xa11ce);
    IndexChain fork_at_third_base(SECOND_TARGET, 2016, 0x51de);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    BOOST_CHECK(cache->GenesisHash() == genesis);
    BOOST_CHECK(cache->Config() == BuildConfig());

    QuorumBuildError error{QuorumBuildError::INVALID_ARGUMENT};
    const auto first_verified{GetTestVerifiedActive(cache,
                                                    FIRST_TARGET, canonical.Tip(), &error)};
    BOOST_REQUIRE(first_verified);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);
    const auto first{GetTestActive(cache,
                                   FIRST_TARGET, canonical.Tip(), &error)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first == first_verified->RostersPtr());
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto same_verified{GetTestVerifiedActive(cache,
                                                   SECOND_TARGET, canonical.Tip(), &error)};
    BOOST_REQUIRE(same_verified);
    BOOST_CHECK(first_verified == same_verified);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto post_base_fork{GetTestActive(cache,
                                            SECOND_TARGET, fork_after_base.Tip(), &error)};
    BOOST_REQUIRE(post_base_fork);
    BOOST_CHECK(post_base_fork == first);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    const auto base_fork{GetTestActive(cache,
                                       FIRST_TARGET, fork_at_third_base.Tip(), &error)};
    BOOST_REQUIRE(base_fork);
    BOOST_CHECK(base_fork != first);
    const auto base_fork_verified{GetTestVerifiedActive(cache,
                                                        FIRST_TARGET, fork_at_third_base.Tip(), &error)};
    BOOST_REQUIRE(base_fork_verified);
    BOOST_CHECK(base_fork_verified != first_verified);
    BOOST_CHECK(base_fork == base_fork_verified->RostersPtr());
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    BOOST_CHECK((*base_fork)[0].descriptor == (*first)[0].descriptor);
    BOOST_CHECK((*base_fork)[1].descriptor == (*first)[1].descriptor);
    BOOST_CHECK((*base_fork)[2].descriptor.base_hash !=
                (*first)[2].descriptor.base_hash);
    BOOST_CHECK((*base_fork)[3].descriptor.base_hash !=
                (*first)[3].descriptor.base_hash);

    BOOST_CHECK(!GetTestActive(cache,
                               FIRST_TARGET + 1, canonical.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_TARGET_HEIGHT);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    BOOST_CHECK(!GetTestActive(cache,
                               FIRST_TARGET, canonical.At(FIRST_TARGET - 1), &error));
    BOOST_CHECK(error == QuorumBuildError::MISSING_BRANCH_ANCESTOR);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);

    BOOST_REQUIRE(cache->LookupSnapshot(canonical.At(1296)));
    BOOST_REQUIRE(cache->LookupSnapshot(canonical.At(1296)));
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 4);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_never_crosses_beacon_bundles)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    const uint256 genesis{NonNullHash(20'001)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE + 20);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE + 20);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const auto first_bundle{BeaconBundleAtHeight(TARGET_HEIGHT)};
    const auto first{cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), first_bundle)};
    BOOST_REQUIRE(first);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    auto changed_bundle{first_bundle};
    changed_bundle.seeds.back().future_btc_hash = NonNullHash(20'002);
    changed_bundle.recovery_authority_source.normal_beacon =
        changed_bundle.seeds.back();
    BOOST_REQUIRE(changed_bundle.IsStructurallyValid());
    const auto changed{cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), changed_bundle)};
    BOOST_REQUIRE(changed);
    BOOST_CHECK(changed != first);
    // The three exact overlapping beacon/snapshot pairs are reused. Only the
    // changed newest seed may build a distinct roster.
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK(changed->Rosters()[slot].descriptor ==
                    first->Rosters()[slot].descriptor);
    }
    BOOST_CHECK(changed->Rosters().back().descriptor.roster_beacon_hash !=
                first->Rosters().back().descriptor.roster_beacon_hash);
    BOOST_CHECK(cache->GetVerifiedActive(
                    TARGET_HEIGHT, chain.Tip(), first_bundle) == first);
    BOOST_CHECK(cache->GetVerifiedActive(
                    TARGET_HEIGHT, chain.Tip(), changed_bundle) == changed);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);

    auto pending_bundle{first_bundle};
    pending_bundle.seeds.back().state = RosterBeaconState::PENDING;
    pending_bundle.seeds.back().future_btc_hash.SetNull();
    BOOST_REQUIRE(pending_bundle.seeds.back().IsStructurallyValid());
    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), pending_bundle, &error));
    BOOST_CHECK(error == QuorumBuildError::INVALID_ROSTER_BEACON);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
}

BOOST_AUTO_TEST_CASE(unverified_roster_builds_do_not_evict_live_cache)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    const uint256 genesis{NonNullHash(20'100)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE + 20);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE + 20);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const auto live_bundle{BeaconBundleAtHeight(TARGET_HEIGHT)};
    const auto live{cache->GetVerifiedActive(
        TARGET_HEIGHT, chain.Tip(), live_bundle)};
    BOOST_REQUIRE(live);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    for (std::size_t attempt{0};
         attempt < FROZEN_QUORUM_ROSTER_CACHE_CAPACITY + 1;
         ++attempt) {
        auto claimed{live_bundle};
        claimed.seeds.back().future_btc_hash =
            NonNullHash(20'200 + attempt);
        claimed.recovery_authority_source.normal_beacon =
            claimed.seeds.back();
        BOOST_REQUIRE(claimed.IsStructurallyValid());
        BOOST_REQUIRE(cache->GetVerifiedActiveNoPublish(
            TARGET_HEIGHT, chain.Tip(), claimed));
    }
    BOOST_CHECK_EQUAL(
        lookups,
        ACTIVE_QUORUMS + FROZEN_QUORUM_ROSTER_CACHE_CAPACITY + 1);
    BOOST_CHECK(cache->GetVerifiedActive(
                    TARGET_HEIGHT, chain.Tip(), live_bundle) == live);
    BOOST_CHECK_EQUAL(
        lookups,
        ACTIVE_QUORUMS + FROZEN_QUORUM_ROSTER_CACHE_CAPACITY + 1);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_reuses_overlapping_epoch_rosters)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t ROTATED_TARGET{2595};
    constexpr int32_t NEW_BASE_HEIGHT{2592};
    constexpr uint64_t ROOT_HASHES_PER_ROSTER{2'046};
    const uint256 genesis{NonNullHash(24)};
    IndexChain canonical(ROTATED_TARGET, ROTATED_TARGET + 1, 0);
    IndexChain fork_at_new_base(
        ROTATED_TARGET, NEW_BASE_HEIGHT, 0xf04c);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const uint64_t first_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto first{GetTestVerifiedActive(cache,
                                           FIRST_TARGET, canonical.Tip())};
    BOOST_REQUIRE(first);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          first_hashes_before,
                      ACTIVE_QUORUMS * ROOT_HASHES_PER_ROSTER);

    const uint64_t rotation_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto rotated{GetTestVerifiedActive(cache,
                                             ROTATED_TARGET, canonical.Tip())};
    BOOST_REQUIRE(rotated);
    BOOST_CHECK(rotated != first);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          rotation_hashes_before,
                      ROOT_HASHES_PER_ROSTER);
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK(rotated->Rosters()[slot].descriptor ==
                    first->Rosters()[slot + 1].descriptor);
    }

    const uint64_t fork_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto forked{GetTestVerifiedActive(cache,
                                            ROTATED_TARGET, fork_at_new_base.Tip())};
    BOOST_REQUIRE(forked);
    BOOST_CHECK(forked != rotated);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    for (std::size_t slot{0}; slot + 1 < ACTIVE_QUORUMS; ++slot) {
        BOOST_CHECK(forked->Rosters()[slot].descriptor ==
                    first->Rosters()[slot + 1].descriptor);
    }
    BOOST_CHECK(forked->Rosters().back().descriptor.base_hash !=
                rotated->Rosters().back().descriptor.base_hash);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          fork_hashes_before,
                      ROOT_HASHES_PER_ROSTER);
    const uint64_t hit_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(GetTestVerifiedActive(cache,
                                      ROTATED_TARGET, fork_at_new_base.Tip()) == forked);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      hit_hashes_before);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_mint_matches_public_validation)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    constexpr uint32_t SNAPSHOT_LAG{144};
    constexpr uint64_t ROOT_HASHES_PER_ROSTER{2'046};
    constexpr uint64_t ROOT_HASHES_PER_SET{
        ACTIVE_QUORUMS * ROOT_HASHES_PER_ROSTER};
    const uint256 genesis{NonNullHash(28)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::vector<std::shared_ptr<std::vector<OperatorKeyState>>>
        source_aliases;
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        const auto epoch{EpochForHeight(
            Schedule(), index.nHeight + static_cast<int32_t>(SNAPSHOT_LAG))};
        if (!epoch) return std::optional<QuorumSnapshotState>{};
        auto states{std::make_shared<std::vector<OperatorKeyState>>(
            KeyStates(QUORUM_SIZE, *epoch, index.nHeight))};
        for (auto& state : *states) {
            const auto tree_id{GetChildKeyTreeId(
                genesis, state.pro_tx_hash,
                state.global_key.child_key_commitment.generation,
                state.global_key.child_key_commitment.first_epoch)};
            BOOST_REQUIRE(tree_id);
            state.global_key.child_key_commitment.tree_id = *tree_id;
            for (auto& frozen : state.frozen_child_roots) {
                frozen.commitment.tree_id = *tree_id;
            }
        }
        source_aliases.push_back(states);

        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = states;
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG), lookup)};
    BOOST_REQUIRE(cache);

    const uint64_t build_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto cached{GetTestVerifiedActive(cache,
                                            TARGET_HEIGHT, chain.Tip())};
    BOOST_REQUIRE(cached);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          build_hashes_before,
                      ROOT_HASHES_PER_SET);
    BOOST_REQUIRE_EQUAL(source_aliases.size(), ACTIVE_QUORUMS);

    const uint256 source_member{source_aliases.front()->front().pro_tx_hash};
    const std::size_t source_slot{FindMember(
        cached->Rosters().front(), source_member)};
    BOOST_REQUIRE_LT(source_slot, QUORUM_SIZE);
    BOOST_REQUIRE(cached->Rosters().front()
                      .members[source_slot]
                      .child_root);
    const auto cached_child{
        *cached->Rosters().front().members[source_slot].child_root};
    source_aliases.front()->front()
        .frozen_child_roots.front()
        .commitment.root = NonNullHash(280'001);
    BOOST_CHECK(cached->Rosters().front()
                    .members[source_slot]
                    .child_root == cached_child);

    ChainLockVerificationError verification_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    const uint64_t validation_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto fully_validated{VerifiedRosterSet::Create(
        genesis, cached->RostersPtr(), &verification_error)};
    BOOST_REQUIRE(fully_validated);
    BOOST_CHECK(verification_error == ChainLockVerificationError::NONE);
    BOOST_CHECK(SameRosterSet(
        cached->Rosters(), fully_validated->Rosters()));
    BOOST_CHECK(cached->RostersPtr() != fully_validated->RostersPtr());
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          validation_hashes_before,
                      ROOT_HASHES_PER_SET);

    auto mutable_input{
        std::make_shared<FrozenQuorumRosters>(cached->Rosters())};
    FrozenQuorumRostersPtr aliased_input{mutable_input};
    const auto alias_safe{VerifiedRosterSet::Create(
        genesis, aliased_input, &verification_error)};
    BOOST_REQUIRE(alias_safe);
    const uint256 isolated_root{
        alias_safe->Rosters().front().descriptor.member_root};
    mutable_input->front().descriptor.member_root = NonNullHash(280'002);
    mutable_input->front().members.front().pro_tx_hash =
        NonNullHash(280'003);
    BOOST_CHECK(alias_safe->Rosters().front().descriptor.member_root ==
                isolated_root);
    BOOST_CHECK(alias_safe->Rosters().front().members.front().pro_tx_hash !=
                mutable_input->front().members.front().pro_tx_hash);

    auto invalid{
        std::make_shared<FrozenQuorumRosters>(cached->Rosters())};
    invalid->front().members[1].pro_tx_hash =
        invalid->front().members[0].pro_tx_hash;
    verification_error = ChainLockVerificationError::NONE;
    FrozenQuorumRostersPtr invalid_input{invalid};
    BOOST_CHECK(!VerifiedRosterSet::Create(
        genesis, invalid_input, &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::DUPLICATE_MEMBER);
    const uint64_t hit_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(GetTestVerifiedActive(cache,
                                      TARGET_HEIGHT, chain.Tip()) == cached);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      hit_hashes_before);

    const auto independent_cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG), lookup)};
    BOOST_REQUIRE(independent_cache);
    const auto independently_minted{GetTestVerifiedActive(independent_cache,
                                                          TARGET_HEIGHT, chain.Tip())};
    BOOST_REQUIRE(independently_minted);
    BOOST_CHECK(independently_minted != cached);
    BOOST_CHECK(independently_minted->RostersPtr() != cached->RostersPtr());
    BOOST_CHECK(SameRosterSet(
        independently_minted->Rosters(), cached->Rosters()));
}

BOOST_AUTO_TEST_CASE(active_roster_cache_rechecks_cross_roster_child_keys)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t ROTATED_TARGET{2595};
    constexpr uint32_t ROTATED_EPOCH{4};
    constexpr uint32_t SNAPSHOT_LAG{144};
    const uint256 genesis{NonNullHash(25)};
    IndexChain chain(ROTATED_TARGET, ROTATED_TARGET + 1, 0);
    std::size_t lookups{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        const auto epoch{EpochForHeight(
            Schedule(), index.nHeight + static_cast<int32_t>(SNAPSHOT_LAG))};
        if (!epoch) return std::optional<QuorumSnapshotState>{};

        auto states{KeyStates(QUORUM_SIZE, *epoch, index.nHeight)};
        if (*epoch == ROTATED_EPOCH) {
            for (std::size_t member{0}; member < states.size(); ++member) {
                const uint256 tree_id{NonNullHash(150'000 + member)};
                states[member].global_key.child_key_commitment.tree_id = tree_id;
                states[member].frozen_child_roots.front()
                    .commitment.tree_id = tree_id;
            }
            const uint256 prior_owner_tree_id{NonNullHash(50'002)};
            states.front().global_key.child_key_commitment.tree_id =
                prior_owner_tree_id;
            states.front().frozen_child_roots.front().commitment.tree_id =
                prior_owner_tree_id;
        }

        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = SharedOperatorStates(std::move(states));
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG), lookup)};
    BOOST_REQUIRE(cache);
    BOOST_REQUIRE(GetTestVerifiedActive(cache, FIRST_TARGET, chain.Tip()));
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    QuorumBuildError error{QuorumBuildError::NONE};
    const uint64_t failure_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(!GetTestVerifiedActive(cache,
                                       ROTATED_TARGET, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::DUPLICATE_CHILD_KEY);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          failure_hashes_before,
                      2'046U);
    BOOST_REQUIRE(GetTestVerifiedActive(cache, FIRST_TARGET, chain.Tip()));
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!GetTestActive(cache,
                               TARGET_HEIGHT, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
    BOOST_CHECK_EQUAL(lookups, 1U);

    const auto retry{GetTestActive(
        cache, TARGET_HEIGHT, chain.Tip(), &error)};
    BOOST_REQUIRE(retry);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);
    BOOST_CHECK(GetTestActive(cache, TARGET_HEIGHT, chain.Tip()) == retry);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);

    std::size_t uncached_lookups{0};
    const QuorumSnapshotLookup uncached_lookup =
        [&](const CBlockIndex& index) {
            ++uncached_lookups;
            QuorumSnapshotState result;
            result.deterministic_mns = Snapshot(
                index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
            result.operator_key_states = RootedOperatorStatesForSnapshot(
                index, QUORUM_SIZE);
            return std::optional<QuorumSnapshotState>{std::move(result)};
        };
    const auto uncached{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), uncached_lookup,
        /*cache_results=*/false)};
    BOOST_REQUIRE(uncached);
    const uint64_t uncached_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto uncached_first{
        GetTestActive(uncached, TARGET_HEIGHT, chain.Tip())};
    const auto uncached_second{
        GetTestActive(uncached, TARGET_HEIGHT, chain.Tip())};
    BOOST_REQUIRE(uncached_first);
    BOOST_REQUIRE(uncached_second);
    BOOST_CHECK(uncached_first != uncached_second);
    BOOST_CHECK_EQUAL(uncached_lookups, 2 * ACTIVE_QUORUMS);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          uncached_hashes_before,
                      2 * ACTIVE_QUORUMS * 2'046U);

    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        uint256{}, BuildConfig(), uncached_lookup));
    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        genesis, QuorumBuildConfig{}, uncached_lookup));
    BOOST_CHECK(!FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), QuorumSnapshotLookup{}));
}

BOOST_AUTO_TEST_CASE(active_roster_cache_contains_snapshot_lookup_exceptions)
{
    constexpr int32_t TARGET_HEIGHT{2305};
    const uint256 genesis{NonNullHash(26)};
    IndexChain chain(TARGET_HEIGHT, TARGET_HEIGHT + 1, 0);
    std::size_t lookups{0};
    bool throw_next{true};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        if (throw_next) {
            throw_next = false;
            throw std::runtime_error{"snapshot unavailable"};
        }
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    QuorumBuildError error{QuorumBuildError::NONE};
    BOOST_CHECK(!GetTestActive(cache,
                               TARGET_HEIGHT, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
    BOOST_CHECK_EQUAL(lookups, 1U);

    const auto retry{GetTestActive(cache,
                                   TARGET_HEIGHT, chain.Tip(), &error)};
    BOOST_REQUIRE(retry);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);
    BOOST_CHECK(GetTestActive(cache, TARGET_HEIGHT, chain.Tip()) == retry);
    BOOST_CHECK_EQUAL(lookups, 1U + ACTIVE_QUORUMS);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_does_not_cache_rotation_failures)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t ROTATED_TARGET{2595};
    constexpr int32_t NEW_SNAPSHOT_HEIGHT{2448};
    const uint256 genesis{NonNullHash(27)};
    IndexChain chain(ROTATED_TARGET, ROTATED_TARGET + 1, 0);
    std::size_t lookups{0};
    bool fail_rotated_lookup{true};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        ++lookups;
        if (index.nHeight == NEW_SNAPSHOT_HEIGHT && fail_rotated_lookup) {
            fail_rotated_lookup = false;
            return std::optional<QuorumSnapshotState>{};
        }
        QuorumSnapshotState result;
        result.deterministic_mns = Snapshot(
            index.nHeight, index.GetBlockHash(), QUORUM_SIZE);
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    BOOST_REQUIRE(GetTestVerifiedActive(cache, FIRST_TARGET, chain.Tip()));
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS);

    QuorumBuildError error{QuorumBuildError::NONE};
    const uint64_t failure_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(!GetTestVerifiedActive(cache,
                                       ROTATED_TARGET, chain.Tip(), &error));
    BOOST_CHECK(error == QuorumBuildError::SNAPSHOT_LOOKUP_FAILED);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 1);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      failure_hashes_before);

    const uint64_t retry_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto retry{GetTestVerifiedActive(cache,
                                           ROTATED_TARGET, chain.Tip(), &error)};
    BOOST_REQUIRE(retry);
    BOOST_CHECK(error == QuorumBuildError::NONE);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          retry_hashes_before,
                      2'046U);
    const uint64_t hit_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(GetTestVerifiedActive(cache,
                                      ROTATED_TARGET, chain.Tip()) == retry);
    BOOST_CHECK_EQUAL(lookups, ACTIVE_QUORUMS + 2);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      hit_hashes_before);
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const uint64_t build_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto beacon_bundle{BeaconBundleAtHeight(TARGET_HEIGHT)};
    std::array<VerifiedRosterSetPtr, 2> results;
    std::thread first{[&] {
        results[0] = cache->GetVerifiedActive(
            TARGET_HEIGHT, chain.Tip(), beacon_bundle);
    }};
    std::thread second{[&] {
        results[1] = cache->GetVerifiedActive(
            TARGET_HEIGHT, chain.Tip(), beacon_bundle);
    }};
    first.join();
    second.join();

    BOOST_REQUIRE(results[0]);
    BOOST_REQUIRE(results[1]);
    BOOST_CHECK(results[0] == results[1]);
    BOOST_CHECK(GetTestActive(cache, TARGET_HEIGHT, chain.Tip()) ==
                results[0]->RostersPtr());
    BOOST_CHECK_EQUAL(lookups.load(std::memory_order_relaxed),
                      2 * ACTIVE_QUORUMS);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          build_hashes_before,
                      2 * ACTIVE_QUORUMS * 2'046U);
}

BOOST_AUTO_TEST_CASE(active_roster_cache_converges_concurrent_rotations)
{
    constexpr int32_t FIRST_TARGET{2305};
    constexpr int32_t ROTATED_TARGET{2595};
    constexpr int32_t NEW_SNAPSHOT_HEIGHT{2448};
    const uint256 genesis{NonNullHash(26)};
    IndexChain chain(ROTATED_TARGET, ROTATED_TARGET + 1, 0);
    std::atomic<std::size_t> lookups{0};
    std::mutex barrier_mutex;
    std::condition_variable barrier_cv;
    std::size_t arrivals{0};
    const QuorumSnapshotLookup lookup = [&](const CBlockIndex& index) {
        lookups.fetch_add(1, std::memory_order_relaxed);
        if (index.nHeight == NEW_SNAPSHOT_HEIGHT) {
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);
    BOOST_REQUIRE(GetTestVerifiedActive(cache, FIRST_TARGET, chain.Tip()));
    BOOST_CHECK_EQUAL(lookups.load(std::memory_order_relaxed),
                      ACTIVE_QUORUMS);

    const uint64_t rotation_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto beacon_bundle{BeaconBundleAtHeight(ROTATED_TARGET)};
    std::array<VerifiedRosterSetPtr, 2> results;
    std::thread first{[&] {
        results[0] = cache->GetVerifiedActive(
            ROTATED_TARGET, chain.Tip(), beacon_bundle);
    }};
    std::thread second{[&] {
        results[1] = cache->GetVerifiedActive(
            ROTATED_TARGET, chain.Tip(), beacon_bundle);
    }};
    first.join();
    second.join();

    BOOST_REQUIRE(results[0]);
    BOOST_REQUIRE(results[1]);
    BOOST_CHECK(results[0] == results[1]);
    BOOST_CHECK(GetTestVerifiedActive(cache,
                                      ROTATED_TARGET, chain.Tip()) == results[0]);
    BOOST_CHECK_EQUAL(lookups.load(std::memory_order_relaxed),
                      ACTIVE_QUORUMS + 2);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          rotation_hashes_before,
                      2 * 2'046U);
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };
    const auto cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(), lookup)};
    BOOST_REQUIRE(cache);

    const auto retained{GetTestActive(cache,
                                      FIRST_TARGET, chain.Tip())};
    BOOST_REQUIRE(retained);
    const auto retained_descriptor{retained->front().descriptor};
    for (std::size_t context{1}; context < CONTEXTS; ++context) {
        const int32_t target{
            FIRST_TARGET + static_cast<int32_t>(context) * CONTEXT_STRIDE};
        BOOST_REQUIRE(GetTestActive(cache, target, chain.Tip()));
    }
    BOOST_CHECK_EQUAL(lookups, CONTEXTS * ACTIVE_QUORUMS);

    const auto rebuilt{GetTestActive(cache, FIRST_TARGET, chain.Tip())};
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

    const auto original{BuildTestActiveRosters(
        genesis, BuildConfig(SNAPSHOT_LAG), TARGET_HEIGHT, chain.Tip(),
        lookup)};
    BOOST_REQUIRE(original);
    for (std::size_t slot{0}; slot < snapshot_heights.size(); ++slot) {
        chain.indices[snapshot_heights[slot]].pqPaymentProbationStateHash =
            NonNullHash(70'000 + slot);
    }

    const auto checkpointed{BuildTestActiveRosters(
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
    constexpr int32_t TARGET_HEIGHT{2595};
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
        result.operator_key_states = RootedOperatorStatesForSnapshot(
            index, QUORUM_SIZE);
        return std::optional<QuorumSnapshotState>{std::move(result)};
    };

    const auto active_epochs{ActiveEpochsAtHeight(Schedule(), TARGET_HEIGHT)};
    BOOST_REQUIRE(active_epochs);
    const uint32_t newest_epoch{active_epochs->back().epoch};
    RosterBeaconWindow roster_beacons;
    roster_beacons.active = BeaconBundle(newest_epoch);
    roster_beacons.active.recovery_authority_source.normal_beacon =
        roster_beacons.active.seeds.back();
    roster_beacons.next.epoch = newest_epoch + 1;
    BOOST_REQUIRE(roster_beacons.IsStructurallyValid());
    const auto roster_cache{FrozenQuorumRosterCache::Create(
        genesis, BuildConfig(SNAPSHOT_LAG), lookup)};
    BOOST_REQUIRE(roster_cache);
    QuorumBuildError build_error{QuorumBuildError::NONE};
    const auto roster_set{
        roster_cache->GetVerifiedActiveNoPublish(
            TARGET_HEIGHT, side.Tip(), roster_beacons.active,
            &build_error)};
    BOOST_REQUIRE_MESSAGE(
        roster_set, "quorum build error=" << static_cast<int>(build_error));
    const auto& rosters{roster_set->RostersPtr()};
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
    statement.roster_transition =
        RosterAuthorizationTransitionKind::ROTATE;
    statement.roster_authorization_base = {
        statement.previous_chainlock_height,
        statement.previous_chainlock_hash,
        NonNullHash(60'003)};
    statement.roster_beacons = roster_beacons;
    statement.payment_probation_state_hash = NonNullHash(60'001);
    statement.quorum_context_hash = GetQuorumContextHash(
        genesis, TARGET_HEIGHT, statement.block_hash, descriptors);

    RosterBeaconWindow previous_window;
    previous_window.active = BeaconBundle(newest_epoch - 1);
    previous_window.next = ReadyBeaconSeed(newest_epoch);
    RosterAuthorizationVerificationContext live;
    live.predecessor_height = statement.previous_chainlock_height;
    live.predecessor_block_hash = statement.previous_chainlock_hash;
    live.authorization_base = statement.roster_authorization_base;
    live.reset_policy = ResetPolicy();
    live.previous = RosterAuthorizationPriorState{
        NonNullHash(60'002), previous_window};
    live.normal_input = test::MakeSyntheticNormalRosterAuthorizationInput(
        statement, *live.previous);

    const auto set_authorization_hash = [&, previous = live.previous](
                                            ChainLockStatement& value) {
        RosterAuthorizationTransition transition;
        transition.kind = value.roster_transition;
        transition.target_height = value.height;
        transition.target_block_hash = value.block_hash;
        transition.predecessor_height = value.previous_chainlock_height;
        transition.predecessor_block_hash = value.previous_chainlock_hash;
        transition.authorization_base = value.roster_authorization_base;
        transition.previous = previous;
        transition.new_window = value.roster_beacons;
        const auto hash{GetRosterAuthorizationStateHash(genesis, transition)};
        BOOST_REQUIRE(hash);
        value.roster_authorization_state_hash = *hash;
    };
    set_authorization_hash(statement);
    ChainLockVerificationError authorization_error{
        ChainLockVerificationError::NONE};
    const auto authorization_mask{ValidateRosterAuthorizationState(
        genesis, statement, live, &authorization_error)};
    BOOST_REQUIRE_MESSAGE(
        authorization_mask,
        "authorization error=" << static_cast<int>(authorization_error));
    BOOST_CHECK_EQUAL(*authorization_mask, 0b0111);
    BOOST_CHECK_EQUAL(
        *authorization_mask & (uint8_t{1} << (ACTIVE_QUORUMS - 1)), 0);
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto prepared{PreparedChainLockContext::Create(
        Schedule(), statement, roster_set, live, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK_EQUAL(prepared->AuthorizationMask(), 0b0111);

    auto wrong_branch{statement};
    wrong_branch.block_hash = active.At(TARGET_HEIGHT).GetBlockHash();
    set_authorization_hash(wrong_branch);
    auto wrong_branch_live{live};
    wrong_branch_live.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            wrong_branch, *wrong_branch_live.previous);
    BOOST_CHECK(!PreparedChainLockContext::Create(
        Schedule(), wrong_branch, roster_set, wrong_branch_live, &error));
    BOOST_CHECK(error ==
                ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
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
