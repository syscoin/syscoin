// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation_db.h>

#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <functional>

using namespace llmq::pq;

namespace llmq::pq::test {

struct PQPaymentProbationViewCacheStats {
    std::size_t entries{0};
    uint64_t hits{0};
    uint64_t misses{0};
    uint64_t builds{0};
};

class PQPaymentProbationManagerTestAccess {
public:
    static PQPaymentProbationViewCacheStats Stats(
        const PQPaymentProbationManager& manager)
    {
        LOCK(manager.m_mutex);
        return {
            manager.m_state_view_cache.size(),
            manager.m_state_view_cache_hits,
            manager.m_state_view_cache_misses,
            manager.m_state_view_builds};
    }

    static bool IsCached(const PQPaymentProbationManager& manager,
                         const uint256& state_hash)
    {
        LOCK(manager.m_mutex);
        return manager.m_state_view_cache_index.count(state_hash) != 0;
    }

    static constexpr std::size_t Capacity()
    {
        return PQPaymentProbationManager::STATE_VIEW_CACHE_SIZE;
    }

    static std::optional<PQPaymentProbationTransitionView>
    ApplyWithMembership(
        const PQPaymentProbationManager& manager,
        const PQPaymentProbationStateView& previous,
        const PQPaymentProbationTransitionContext& context,
        std::function<PQPaymentProbationMembership(const uint256&)> lookup,
        PQPaymentProbationError* error = nullptr)
    {
        return manager.ApplyTransitionWithMembership(
            previous, context, std::move(lookup), error);
    }

    static bool AdvanceGenerationIfUnlocked(
        PQPaymentProbationManager& manager)
    {
        TRY_LOCK(manager.m_mutex, lock);
        if (!lock) return false;
        ++manager.m_state_view_generation;
        return true;
    }

    static bool IsUnlocked(PQPaymentProbationManager& manager)
    {
        TRY_LOCK(manager.m_mutex, lock);
        return static_cast<bool>(lock);
    }
};

} // namespace llmq::pq::test

namespace {

uint256 NonNullHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value == 0 ? 1 : value;
    return hash;
}

uint256 MemberHash(std::size_t value)
{
    uint256 hash;
    ++value;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    return hash;
}

DBParams MemoryDB()
{
    return DBParams{
        .path = fs::PathFromString("testdb_pq_payment_probation"),
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
}

DBParams DiskDB(const fs::path& path, bool wipe)
{
    return DBParams{
        .path = path,
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = wipe,
    };
}

PQPaymentProbationState StateAtEpoch(uint32_t epoch, uint8_t tag)
{
    PQPaymentProbationState state;
    state.cursor.has_receipt = 1;
    state.cursor.receipt = {
        epoch, static_cast<int32_t>(1'000 + epoch), NonNullHash(tag)};
    state.entries.push_back(
        {NonNullHash(static_cast<uint8_t>(100 + tag)), 1, -1});
    return state;
}

uint256 Commit(PQPaymentProbationManager& manager,
               const PQPaymentProbationState& state)
{
    BOOST_REQUIRE(state.IsStructurallyValid());
    const auto state_hash{GetPQPaymentProbationStateHash(state)};
    BOOST_REQUIRE(state_hash);
    BOOST_REQUIRE(manager.CommitState(state, *state_hash,
                                      /*fJustCheck=*/false));
    return *state_hash;
}

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

PQPaymentProbationTransitionInput TransitionInput(uint32_t epoch,
                                                   uint8_t tag,
                                                   std::size_t observed_count =
                                                       QUORUM_THRESHOLD)
{
    PQPaymentProbationTransitionInput input;
    input.receipt = {
        epoch, static_cast<int32_t>(2'000 + epoch), NonNullHash(tag)};
    input.roster_valid_members.fill(0xff);
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        input.frozen_roster[member] = MemberHash(member);
        input.existing_pro_tx_hashes.push_back(
            input.frozen_roster[member]);
        input.current_valid_pro_tx_hashes.push_back(
            input.frozen_roster[member]);
        if (member < observed_count) SetBit(input.observed_members, member);
    }
    std::sort(input.existing_pro_tx_hashes.begin(),
              input.existing_pro_tx_hashes.end());
    std::sort(input.current_valid_pro_tx_hashes.begin(),
              input.current_valid_pro_tx_hashes.end());
    BOOST_REQUIRE(input.IsStructurallyValid());
    return input;
}

PaymentAuditStoreCheckpoint Checkpoint(uint32_t epoch, uint8_t tag)
{
    PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = epoch;
    checkpoint.covered_through_height = 2'000 + epoch;
    checkpoint.covered_through_hash = NonNullHash(tag);
    checkpoint.authenticated_probation_state_hash =
        NonNullHash(static_cast<uint8_t>(tag + 1));
    checkpoint.authorizing_target_height =
        checkpoint.covered_through_height + 10;
    checkpoint.authorizing_target_hash =
        NonNullHash(static_cast<uint8_t>(tag + 2));
    checkpoint.authorizing_chainlock_logical_id =
        NonNullHash(static_cast<uint8_t>(tag + 3));
    checkpoint.authorizing_chainlock_witness_id =
        NonNullHash(static_cast<uint8_t>(tag + 4));
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    return checkpoint;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_probation_db_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hash_addressed_commit_read_and_barrier)
{
    using Access = test::PQPaymentProbationManagerTestAccess;
    PQPaymentProbationManager manager{MemoryDB()};
    PQPaymentProbationState empty;
    BOOST_CHECK(manager.GetState(manager.EmptyStateHash(), empty));
    BOOST_CHECK(empty == PQPaymentProbationState{});

    PQPaymentProbationState state;
    state.entries.push_back({NonNullHash(1), 2, -1});
    const auto state_hash{GetPQPaymentProbationStateHash(state)};
    BOOST_REQUIRE(state_hash);

    BOOST_CHECK(manager.CommitState(state, *state_hash,
                                    /*fJustCheck=*/true));
    PQPaymentProbationState loaded;
    BOOST_CHECK(!manager.GetState(*state_hash, loaded));
    auto stats{Access::Stats(manager)};
    BOOST_CHECK_EQUAL(stats.entries, 0U);
    BOOST_CHECK_EQUAL(stats.builds, 0U);

    BOOST_CHECK(manager.CommitState(state, *state_hash,
                                    /*fJustCheck=*/false));
    stats = Access::Stats(manager);
    BOOST_CHECK_EQUAL(stats.entries, 1U);
    BOOST_CHECK_EQUAL(stats.builds, 1U);
    BOOST_CHECK(manager.GetState(*state_hash, loaded));
    BOOST_CHECK(loaded == state);

    manager.StateDatabaseForTesting().FailNextFlushBatchForTesting();
    BOOST_CHECK(manager.Flush(/*fSync=*/false));
    BOOST_CHECK_THROW((void)manager.Flush(/*fSync=*/true), dbwrapper_error);
    BOOST_CHECK(manager.Flush(/*fSync=*/true));

    BOOST_CHECK(!manager.CommitState(state, NonNullHash(9), false));
}

BOOST_AUTO_TEST_CASE(shared_views_are_authenticated_indexed_and_bounded)
{
    using Access = test::PQPaymentProbationManagerTestAccess;
    PQPaymentProbationManager manager{MemoryDB()};
    BOOST_CHECK_EQUAL(manager.StateDatabaseForTesting().GetReadCacheSize(),
                      0U);

    PQPaymentProbationStateView empty_a;
    PQPaymentProbationStateView empty_b;
    BOOST_REQUIRE(manager.GetStateView(manager.EmptyStateHash(), empty_a));
    BOOST_REQUIRE(manager.GetStateView(manager.EmptyStateHash(), empty_b));
    BOOST_CHECK(empty_a.IsValid());
    BOOST_CHECK(empty_a.SharesStateWith(empty_b));
    BOOST_CHECK(empty_a.StateHash() == manager.EmptyStateHash());
    BOOST_REQUIRE(empty_a.State() != nullptr);
    BOOST_CHECK(*empty_a.State() == PQPaymentProbationState{});
    BOOST_CHECK_EQUAL(Access::Stats(manager).entries, 0U);

    PQPaymentProbationState first;
    first.entries = {
        {NonNullHash(20), 1, 9},
        {NonNullHash(21), 2, 10},
    };
    const uint256 first_hash{Commit(manager, first)};
    PQPaymentProbationStateView first_a;
    PQPaymentProbationStateView first_b;
    BOOST_REQUIRE(manager.GetStateView(first_hash, first_a));
    BOOST_REQUIRE(manager.GetStateView(first_hash, first_b));
    BOOST_CHECK(first_a.SharesStateWith(first_b));
    BOOST_CHECK_EQUAL(first_a.MissCount(NonNullHash(20)), 1U);
    BOOST_CHECK_EQUAL(first_a.MissCount(NonNullHash(21)), 2U);
    BOOST_CHECK(first_a.IsPaymentWithheld(NonNullHash(21)));
    BOOST_CHECK_EQUAL(first_a.PaymentEligibleSinceHeight(NonNullHash(20)),
                      9);
    BOOST_CHECK_EQUAL(first_a.MissCount(NonNullHash(22)), 0U);
    BOOST_CHECK_EQUAL(first_a.PaymentEligibleSinceHeight(NonNullHash(22)),
                      -1);

    for (std::size_t offset{1}; offset <= Access::Capacity(); ++offset) {
        Commit(manager,
               StateAtEpoch(static_cast<uint32_t>(100 + offset),
                            static_cast<uint8_t>(30 + offset)));
    }
    auto stats{Access::Stats(manager)};
    BOOST_CHECK_EQUAL(stats.entries, Access::Capacity());
    BOOST_CHECK(!Access::IsCached(manager, first_hash));

    PQPaymentProbationStateView rebuilt;
    BOOST_REQUIRE(manager.GetStateView(first_hash, rebuilt));
    BOOST_CHECK(!rebuilt.SharesStateWith(first_a));
    BOOST_CHECK_EQUAL(rebuilt.MissCount(NonNullHash(21)), 2U);
    stats = Access::Stats(manager);
    BOOST_CHECK_EQUAL(stats.entries, Access::Capacity());
    BOOST_CHECK_GE(stats.hits, 4U);
    BOOST_CHECK_GE(stats.misses, 1U);
    BOOST_CHECK_GE(stats.builds, Access::Capacity() + 2);
    BOOST_CHECK_EQUAL(manager.StateDatabaseForTesting().GetReadCacheSize(),
                      0U);
}

BOOST_AUTO_TEST_CASE(authenticated_transition_reuses_exact_backing)
{
    using Access = test::PQPaymentProbationManagerTestAccess;
    PQPaymentProbationManager manager{MemoryDB()};
    PQPaymentProbationStateView previous;
    BOOST_REQUIRE(manager.GetStateView(manager.EmptyStateHash(), previous));

    const auto transition{
        manager.ApplyTransition(previous, TransitionInput(1, 80))};
    BOOST_REQUIRE(transition);
    BOOST_REQUIRE(transition->IsValid());
    BOOST_CHECK(transition->PreviousStateHash() ==
                manager.EmptyStateHash());
    BOOST_CHECK(!Access::IsCached(manager,
                                  transition->Result().StateHash()));

    const auto before_check{Access::Stats(manager)};
    PQPaymentProbationStateView unpublished;
    BOOST_CHECK(manager.CommitTransition(*transition,
                                         /*fJustCheck=*/true,
                                         &unpublished));
    BOOST_CHECK(!unpublished.IsValid());
    BOOST_CHECK(!Access::IsCached(manager,
                                  transition->Result().StateHash()));
    BOOST_CHECK_EQUAL(Access::Stats(manager).entries,
                      before_check.entries);

    PQPaymentProbationStateView published;
    BOOST_REQUIRE(manager.CommitTransition(*transition,
                                           /*fJustCheck=*/false,
                                           &published));
    BOOST_CHECK(published.SharesStateWith(transition->Result()));
    BOOST_CHECK(Access::IsCached(manager, published.StateHash()));

    // Replaying the same verified transition resolves the already-published
    // exact root without constructing or hashing another state.
    const auto before_replay{Access::Stats(manager)};
    PQPaymentProbationStateView replayed;
    BOOST_REQUIRE(manager.CommitTransition(*transition,
                                           /*fJustCheck=*/false,
                                           &replayed));
    BOOST_CHECK(replayed.SharesStateWith(published));
    BOOST_CHECK_EQUAL(Access::Stats(manager).builds,
                      before_replay.builds);

    // Reorg selects the authenticated parent root directly; it never rebuilds
    // state by applying the compatibility undo vector.
    PQPaymentProbationStateView restored_parent;
    BOOST_REQUIRE(manager.GetStateView(
        transition->PreviousStateHash(), restored_parent));
    BOOST_CHECK(restored_parent.SharesStateWith(previous));
}

BOOST_AUTO_TEST_CASE(authenticated_transition_rejects_foreign_manager)
{
    PQPaymentProbationManager first{MemoryDB()};
    PQPaymentProbationManager second{MemoryDB()};
    PQPaymentProbationStateView first_previous;
    BOOST_REQUIRE(first.GetStateView(first.EmptyStateHash(), first_previous));

    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    BOOST_CHECK(!second.ApplyTransition(
        first_previous, TransitionInput(2, 81), &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_STATE);

    const auto transition{
        first.ApplyTransition(first_previous, TransitionInput(2, 82))};
    BOOST_REQUIRE(transition);
    BOOST_CHECK(!second.CommitTransition(*transition,
                                         /*fJustCheck=*/false));
    PQPaymentProbationStateView absent;
    BOOST_CHECK(!second.GetStateView(
        transition->Result().StateHash(), absent));
}

BOOST_AUTO_TEST_CASE(compact_transition_matches_raw_corpus)
{
    PQPaymentProbationManager manager{MemoryDB()};
    PQPaymentProbationStateView previous_view;
    BOOST_REQUIRE(manager.GetStateView(
        manager.EmptyStateHash(), previous_view));
    PQPaymentProbationState previous_raw;

    for (uint32_t epoch{1}; epoch <= 24; ++epoch) {
        const auto input{TransitionInput(
            epoch, static_cast<uint8_t>(100 + epoch),
            (epoch * 37) % (QUORUM_SIZE + 1))};
        const auto raw{ApplyPQPaymentProbationTransition(
            previous_raw, input)};
        const auto compact{manager.ApplyTransition(previous_view, input)};
        BOOST_REQUIRE(raw);
        BOOST_REQUIRE(compact);
        BOOST_REQUIRE(compact->Result().State() != nullptr);
        BOOST_CHECK(*compact->Result().State() == raw->state);
        BOOST_CHECK(compact->PreviousStateHash() ==
                    raw->undo.previous_state_hash);
        BOOST_CHECK(compact->AppliedReceipt() ==
                    raw->undo.applied_receipt);
        BOOST_CHECK(compact->Result().StateHash() ==
                    raw->undo.applied_state_hash);

        PQPaymentProbationStateView published;
        BOOST_REQUIRE(manager.CommitTransition(
            *compact, /*fJustCheck=*/false, &published));
        BOOST_CHECK(published.SharesStateWith(compact->Result()));
        previous_view = std::move(published);
        previous_raw = raw->state;
    }
}

BOOST_AUTO_TEST_CASE(private_membership_lookup_is_single_shot_and_lock_free)
{
    using Access = test::PQPaymentProbationManagerTestAccess;
    PQPaymentProbationManager manager{MemoryDB()};
    auto input{TransitionInput(
        /*epoch=*/1, /*tag=*/125,
        PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS + 3)};
    const auto absent{input.frozen_roster[0]};
    const auto observed_invalid{input.frozen_roster[1]};
    const auto missed_valid{input.frozen_roster[350]};
    const auto missed_invalid{input.frozen_roster[351]};
    const auto erase = [](auto& values, const uint256& value) {
        values.erase(std::lower_bound(values.begin(), values.end(), value));
    };
    erase(input.existing_pro_tx_hashes, absent);
    erase(input.current_valid_pro_tx_hashes, absent);
    erase(input.current_valid_pro_tx_hashes, observed_invalid);
    erase(input.current_valid_pro_tx_hashes, missed_invalid);
    BOOST_REQUIRE(input.IsStructurallyValid());

    PQPaymentProbationState previous;
    previous.entries = {
        {absent, 1, -1},
        {observed_invalid, 1, -1},
        {missed_valid, 1, -1},
        {missed_invalid, 1, -1},
    };
    std::sort(previous.entries.begin(), previous.entries.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    const uint256 previous_hash{Commit(manager, previous)};
    PQPaymentProbationStateView previous_view;
    BOOST_REQUIRE(manager.GetStateView(previous_hash, previous_view));

    const auto expected{ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(expected);
    std::size_t lookups{0};
    std::size_t overlapping_lookups{0};
    bool always_unlocked{true};
    const auto actual{Access::ApplyWithMembership(
        manager, previous_view, input,
        [&](const uint256& pro_tx_hash) {
            ++lookups;
            if (pro_tx_hash == missed_valid) ++overlapping_lookups;
            always_unlocked = always_unlocked && Access::IsUnlocked(manager);
            if (pro_tx_hash == absent) {
                return PQPaymentProbationMembership::ABSENT;
            }
            if (pro_tx_hash == observed_invalid ||
                pro_tx_hash == missed_invalid) {
                return PQPaymentProbationMembership::PRESENT_INVALID;
            }
            return PQPaymentProbationMembership::PRESENT_VALID;
        })};
    BOOST_REQUIRE(actual);
    BOOST_REQUIRE(actual->Result().State() != nullptr);
    BOOST_CHECK(always_unlocked);
    BOOST_CHECK_EQUAL(
        lookups, previous.entries.size() + QUORUM_SIZE);
    BOOST_CHECK_EQUAL(overlapping_lookups, 2U);
    BOOST_CHECK(*actual->Result().State() == expected->state);
    BOOST_CHECK(actual->PreviousStateHash() ==
                expected->undo.previous_state_hash);
    BOOST_CHECK(actual->Result().StateHash() ==
                expected->undo.applied_state_hash);
    BOOST_CHECK_EQUAL(actual->Result().MissCount(absent), 0U);
    BOOST_CHECK_EQUAL(actual->Result().MissCount(observed_invalid), 0U);
    BOOST_CHECK_EQUAL(actual->Result().MissCount(missed_valid), 2U);
    BOOST_CHECK_EQUAL(actual->Result().MissCount(missed_invalid), 1U);
}

BOOST_AUTO_TEST_CASE(private_membership_lookup_is_provenance_fenced)
{
    using Access = test::PQPaymentProbationManagerTestAccess;
    PQPaymentProbationManager first{MemoryDB()};
    PQPaymentProbationManager second{MemoryDB()};
    PQPaymentProbationStateView first_view;
    BOOST_REQUIRE(first.GetStateView(first.EmptyStateHash(), first_view));
    const auto input{TransitionInput(/*epoch=*/1, /*tag=*/126)};

    std::size_t foreign_lookups{0};
    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    BOOST_CHECK(!Access::ApplyWithMembership(
        second, first_view, input,
        [&](const uint256&) {
            ++foreign_lookups;
            return PQPaymentProbationMembership::PRESENT_VALID;
        },
        &error));
    BOOST_CHECK_EQUAL(foreign_lookups, 0U);
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_STATE);

    bool advanced{false};
    std::size_t lookups{0};
    error = PQPaymentProbationError::NONE;
    BOOST_CHECK(!Access::ApplyWithMembership(
        first, first_view, input,
        [&](const uint256&) {
            ++lookups;
            if (!advanced) {
                advanced = Access::AdvanceGenerationIfUnlocked(first);
            }
            return PQPaymentProbationMembership::PRESENT_VALID;
        },
        &error));
    BOOST_CHECK(advanced);
    BOOST_CHECK_GT(lookups, 0U);
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_STATE);
}

BOOST_AUTO_TEST_CASE(probation_survives_process_restart)
{
    const fs::path path{m_path_root / "pq_payment_probation_restart"};
    const uint256 pro_tx_hash{NonNullHash(42)};
    uint256 state_hash;

    {
        PQPaymentProbationManager manager{DiskDB(path, /*wipe=*/true)};
        PQPaymentProbationState state;
        state.entries.push_back({pro_tx_hash, 2, -1});
        const auto expected_hash{GetPQPaymentProbationStateHash(state)};
        BOOST_REQUIRE(expected_hash);
        state_hash = *expected_hash;
        BOOST_REQUIRE(manager.CommitState(state, state_hash,
                                          /*fJustCheck=*/false));
        BOOST_REQUIRE(manager.Flush(/*fSync=*/true));
    }

    PQPaymentProbationManager restarted{DiskDB(path, /*wipe=*/false)};
    PQPaymentProbationStateView restored;
    BOOST_REQUIRE(restarted.GetStateView(state_hash, restored));
    BOOST_CHECK_EQUAL(restored.MissCount(pro_tx_hash), 2U);
    BOOST_CHECK(restored.IsPaymentWithheld(pro_tx_hash));
    BOOST_CHECK_EQUAL(restarted.StateDatabaseForTesting().GetReadCacheSize(),
                      0U);
}

BOOST_AUTO_TEST_CASE(checkpoint_gc_is_durable_and_preserves_retained_roots)
{
    const fs::path path{m_path_root / "pq_payment_probation_gc"};
    const auto checkpoint{Checkpoint(/*epoch=*/5, /*tag=*/40)};
    uint256 pruned_hash;
    uint256 retained_hash;
    uint256 newer_hash;
    uint256 cursorless_hash;
    uint256 empty_hash;

    {
        PQPaymentProbationManager manager{DiskDB(path, /*wipe=*/true)};
        pruned_hash = Commit(manager, StateAtEpoch(/*epoch=*/4, /*tag=*/1));
        retained_hash = Commit(manager, StateAtEpoch(/*epoch=*/5, /*tag=*/2));
        newer_hash = Commit(manager, StateAtEpoch(/*epoch=*/6, /*tag=*/3));

        PQPaymentProbationState cursorless;
        cursorless.entries.push_back({NonNullHash(200), 1, -1});
        cursorless_hash = Commit(manager, cursorless);
        empty_hash = manager.EmptyStateHash();
        PQPaymentProbationStateView empty_before_gc;
        BOOST_REQUIRE(manager.GetStateView(empty_hash, empty_before_gc));

        // Warm the immutable view cache before pruning. The tombstone path
        // drops manager ownership while existing readers finish safely.
        PQPaymentProbationStateView pruned_view;
        PQPaymentProbationStateView retained_view;
        BOOST_REQUIRE(manager.GetStateView(pruned_hash, pruned_view));
        BOOST_REQUIRE(manager.GetStateView(retained_hash, retained_view));
        const auto stale_transition{manager.ApplyTransition(
            pruned_view, TransitionInput(/*epoch=*/5, /*tag=*/83))};
        BOOST_REQUIRE(stale_transition);
        const uint256 stale_result_hash{
            stale_transition->Result().StateHash()};
        const uint64_t previous_generation{
            manager.StateViewGeneration()};

        const std::array<uint256, 1> retained{retained_hash};
        BOOST_CHECK(!manager.IsGCCompleteForCheckpoint(checkpoint));
        BOOST_REQUIRE(manager.PruneStatesThroughCheckpoint(
            checkpoint, retained));
        BOOST_CHECK(manager.IsGCCompleteForCheckpoint(checkpoint));
        BOOST_CHECK_GT(manager.StateViewGeneration(), previous_generation);
        BOOST_CHECK(!manager.CommitTransition(
            *stale_transition, /*fJustCheck=*/false));
        BOOST_CHECK(!manager.ApplyTransition(
            retained_view, TransitionInput(/*epoch=*/6, /*tag=*/84)));
        BOOST_CHECK(!manager.ApplyTransition(
            empty_before_gc, TransitionInput(/*epoch=*/1, /*tag=*/85)));

        PQPaymentProbationStateView loaded_view;
        BOOST_CHECK(!manager.GetStateView(pruned_hash, loaded_view));
        BOOST_CHECK(!manager.GetStateView(stale_result_hash, loaded_view));
        BOOST_CHECK(!loaded_view.IsValid());
        BOOST_CHECK(!test::PQPaymentProbationManagerTestAccess::IsCached(
            manager, pruned_hash));
        BOOST_CHECK(pruned_view.IsValid());
        BOOST_CHECK_EQUAL(pruned_view.MissCount(NonNullHash(101)), 1U);
        BOOST_REQUIRE(manager.GetStateView(retained_hash, loaded_view));
        BOOST_CHECK(!loaded_view.SharesStateWith(retained_view));
        BOOST_CHECK(manager.ApplyTransition(
            loaded_view, TransitionInput(/*epoch=*/6, /*tag=*/86)));

        PQPaymentProbationState loaded;
        BOOST_CHECK(manager.GetState(retained_hash, loaded));
        BOOST_CHECK(manager.GetState(newer_hash, loaded));
        BOOST_CHECK(manager.GetState(cursorless_hash, loaded));
        BOOST_CHECK(manager.GetState(empty_hash, loaded));
        BOOST_CHECK(loaded == PQPaymentProbationState{});
        PQPaymentProbationStateView empty_after_gc;
        BOOST_REQUIRE(manager.GetStateView(empty_hash, empty_after_gc));
        BOOST_CHECK(!empty_after_gc.SharesStateWith(empty_before_gc));
    }

    {
        PQPaymentProbationManager restarted{DiskDB(path, /*wipe=*/false)};
        BOOST_CHECK(restarted.IsGCCompleteForCheckpoint(checkpoint));
        PQPaymentProbationState loaded;
        BOOST_CHECK(!restarted.GetState(pruned_hash, loaded));
        BOOST_CHECK(restarted.GetState(retained_hash, loaded));
        BOOST_CHECK(restarted.GetState(newer_hash, loaded));
        BOOST_CHECK(restarted.GetState(cursorless_hash, loaded));
        BOOST_CHECK(restarted.GetState(empty_hash, loaded));
        BOOST_CHECK(loaded == PQPaymentProbationState{});
    }

    // Chainstate rebuilds wipe this state-owned marker along with the roots,
    // forcing the archive checkpoint to run one repair pass after replay.
    PQPaymentProbationManager rebuilt{DiskDB(path, /*wipe=*/true)};
    BOOST_CHECK(!rebuilt.IsGCCompleteForCheckpoint(checkpoint));
}

BOOST_AUTO_TEST_CASE(checkpoint_gc_validates_every_record_before_erasing)
{
    PQPaymentProbationManager manager{MemoryDB()};
    const auto covered{StateAtEpoch(/*epoch=*/7, /*tag=*/10)};
    const uint256 covered_hash{Commit(manager, covered)};
    const auto corrupt{StateAtEpoch(/*epoch=*/8, /*tag=*/11)};
    const uint256 wrong_hash{NonNullHash(250)};
    BOOST_REQUIRE(GetPQPaymentProbationStateHash(corrupt) != wrong_hash);
    BOOST_REQUIRE(manager.StateDatabaseForTesting().WriteThrough(
        wrong_hash, corrupt, /*fSync=*/false));
    PQPaymentProbationStateView corrupt_view;
    BOOST_CHECK(!manager.GetStateView(wrong_hash, corrupt_view));
    BOOST_CHECK(!corrupt_view.IsValid());
    BOOST_CHECK(!test::PQPaymentProbationManagerTestAccess::IsCached(
        manager, wrong_hash));

    BOOST_CHECK(!manager.PruneStatesThroughCheckpoint(
        Checkpoint(/*epoch=*/10, /*tag=*/50),
        std::span<const uint256>{}));

    // Validation happens before any tombstones are staged.
    PQPaymentProbationState loaded;
    BOOST_CHECK(manager.GetState(covered_hash, loaded));
    BOOST_CHECK(loaded == covered);
}

BOOST_AUTO_TEST_CASE(checkpoint_gc_rejects_missing_or_null_retained_roots)
{
    PQPaymentProbationManager manager{MemoryDB()};
    const auto covered{StateAtEpoch(/*epoch=*/9, /*tag=*/20)};
    const uint256 covered_hash{Commit(manager, covered)};

    const std::array<uint256, 1> missing{NonNullHash(251)};
    const auto checkpoint{Checkpoint(/*epoch=*/10, /*tag=*/60)};
    BOOST_CHECK(!manager.PruneStatesThroughCheckpoint(checkpoint, missing));

    const std::array<uint256, 1> null_retained{uint256{}};
    BOOST_CHECK(!manager.PruneStatesThroughCheckpoint(
        checkpoint, null_retained));

    PQPaymentProbationState loaded;
    BOOST_CHECK(manager.GetState(covered_hash, loaded));
    BOOST_CHECK(loaded == covered);
}

BOOST_AUTO_TEST_CASE(completed_checkpoint_is_a_zero_flush_noop)
{
    PQPaymentProbationManager manager{MemoryDB()};
    const auto checkpoint{Checkpoint(/*epoch=*/12, /*tag=*/70)};
    const uint64_t initial_generation{manager.StateViewGeneration()};
    PQPaymentProbationStateView stale_empty;
    BOOST_REQUIRE(manager.GetStateView(
        manager.EmptyStateHash(), stale_empty));
    const auto stale_transition{manager.ApplyTransition(
        stale_empty, TransitionInput(/*epoch=*/1, /*tag=*/87))};
    BOOST_REQUIRE(stale_transition);
    BOOST_REQUIRE(manager.PruneStatesThroughCheckpoint(
        checkpoint, std::span<const uint256>{}));
    const uint64_t completed_generation{manager.StateViewGeneration()};
    BOOST_CHECK_GT(completed_generation, initial_generation);
    BOOST_CHECK(!manager.CommitTransition(
        *stale_transition, /*fJustCheck=*/false));
    BOOST_CHECK(!manager.ApplyTransition(
        stale_empty, TransitionInput(/*epoch=*/1, /*tag=*/88)));
    PQPaymentProbationStateView fresh_empty;
    BOOST_REQUIRE(manager.GetStateView(
        manager.EmptyStateHash(), fresh_empty));
    BOOST_CHECK(manager.ApplyTransition(
        fresh_empty, TransitionInput(/*epoch=*/1, /*tag=*/89)));
    BOOST_REQUIRE(manager.IsGCCompleteForCheckpoint(checkpoint));

    // The exact completed checkpoint returns before the pre-scan durability
    // barrier. A newer authorizer for the same deletion boundary does too.
    // The injected failure remains armed for the explicit flush.
    manager.StateDatabaseForTesting().FailNextFlushBatchForTesting();
    BOOST_CHECK(manager.PruneStatesThroughCheckpoint(
        checkpoint, std::span<const uint256>{}));
    BOOST_CHECK_EQUAL(manager.StateViewGeneration(), completed_generation);

    auto refreshed_authorizer{checkpoint};
    refreshed_authorizer.authorizing_target_height++;
    refreshed_authorizer.authorizing_target_hash = NonNullHash(80);
    refreshed_authorizer.authorizing_chainlock_logical_id = NonNullHash(81);
    refreshed_authorizer.authorizing_chainlock_witness_id = NonNullHash(82);
    BOOST_REQUIRE(refreshed_authorizer.IsStructurallyValid());
    BOOST_CHECK(manager.IsGCCompleteForCheckpoint(refreshed_authorizer));
    BOOST_CHECK(manager.PruneStatesThroughCheckpoint(
        refreshed_authorizer, std::span<const uint256>{}));
    BOOST_CHECK_EQUAL(manager.StateViewGeneration(), completed_generation);
    BOOST_CHECK_THROW((void)manager.Flush(/*fSync=*/true), dbwrapper_error);
    BOOST_CHECK(manager.Flush(/*fSync=*/true));

    auto conflicting{refreshed_authorizer};
    conflicting.authenticated_probation_state_hash = NonNullHash(83);
    BOOST_REQUIRE(conflicting.IsStructurallyValid());
    BOOST_CHECK(!manager.IsGCCompleteForCheckpoint(conflicting));
    BOOST_CHECK(!manager.PruneStatesThroughCheckpoint(
        conflicting, std::span<const uint256>{}));
}

BOOST_AUTO_TEST_SUITE_END()
