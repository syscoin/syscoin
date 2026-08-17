// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation_db.h>

#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value == 0 ? 1 : value;
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_probation_db_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hash_addressed_commit_read_and_barrier)
{
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

    BOOST_CHECK(manager.CommitState(state, *state_hash,
                                    /*fJustCheck=*/false));
    BOOST_CHECK(manager.GetState(*state_hash, loaded));
    BOOST_CHECK(loaded == state);

    manager.StateDatabaseForTesting().FailNextFlushBatchForTesting();
    BOOST_CHECK(manager.Flush(/*fSync=*/false));
    BOOST_CHECK_THROW((void)manager.Flush(/*fSync=*/true), dbwrapper_error);
    BOOST_CHECK(manager.Flush(/*fSync=*/true));

    BOOST_CHECK(!manager.CommitState(state, NonNullHash(9), false));
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
    PQPaymentProbationState restored;
    BOOST_REQUIRE(restarted.GetState(state_hash, restored));
    BOOST_CHECK_EQUAL(restored.MissCount(pro_tx_hash), 2U);
    BOOST_CHECK(restored.IsPaymentWithheld(pro_tx_hash));
}

BOOST_AUTO_TEST_CASE(checkpoint_gc_is_durable_and_preserves_retained_roots)
{
    const fs::path path{m_path_root / "pq_payment_probation_gc"};
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

        // Warm the read cache before pruning. The tombstone path must evict
        // this copy as well as deleting the persisted record.
        PQPaymentProbationState loaded;
        BOOST_REQUIRE(manager.GetState(pruned_hash, loaded));

        const std::array<uint256, 1> retained{retained_hash};
        BOOST_REQUIRE(manager.PruneStatesThroughEpoch(
            /*prune_through_epoch=*/5, retained));

        BOOST_CHECK(!manager.GetState(pruned_hash, loaded));
        BOOST_CHECK(manager.GetState(retained_hash, loaded));
        BOOST_CHECK(manager.GetState(newer_hash, loaded));
        BOOST_CHECK(manager.GetState(cursorless_hash, loaded));
        BOOST_CHECK(manager.GetState(empty_hash, loaded));
        BOOST_CHECK(loaded == PQPaymentProbationState{});
    }

    PQPaymentProbationManager restarted{DiskDB(path, /*wipe=*/false)};
    PQPaymentProbationState loaded;
    BOOST_CHECK(!restarted.GetState(pruned_hash, loaded));
    BOOST_CHECK(restarted.GetState(retained_hash, loaded));
    BOOST_CHECK(restarted.GetState(newer_hash, loaded));
    BOOST_CHECK(restarted.GetState(cursorless_hash, loaded));
    BOOST_CHECK(restarted.GetState(empty_hash, loaded));
    BOOST_CHECK(loaded == PQPaymentProbationState{});
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

    BOOST_CHECK(!manager.PruneStatesThroughEpoch(
        /*prune_through_epoch=*/10, std::span<const uint256>{}));

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
    BOOST_CHECK(!manager.PruneStatesThroughEpoch(
        /*prune_through_epoch=*/10, missing));

    const std::array<uint256, 1> null_retained{uint256{}};
    BOOST_CHECK(!manager.PruneStatesThroughEpoch(
        /*prune_through_epoch=*/10, null_retained));

    PQPaymentProbationState loaded;
    BOOST_CHECK(manager.GetState(covered_hash, loaded));
    BOOST_CHECK(loaded == covered);
}

BOOST_AUTO_TEST_SUITE_END()
