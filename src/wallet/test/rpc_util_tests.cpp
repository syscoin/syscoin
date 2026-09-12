// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/pq_key_schedule.h>
#include <wallet/rpc/util.h>

#include <hash.h>
#include <llmq/pq_operator_key_state.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace wallet {

namespace {

uint32_t FirstMutablePQEpoch(int32_t next_height)
{
    llmq::pq::ChainLockScheduleConfig schedule;
    schedule.epoch_origin = 1440;
    const auto view{llmq::pq::DeriveOperatorKeyScheduleView(
        schedule, next_height, /*registration_cutoff_blocks=*/144,
        /*future_horizon_epochs=*/8)};
    BOOST_REQUIRE(view);
    return view->first_mutable_epoch;
}

llmq::pq::ChildKeyTreeCommitment ScheduleBoundTestCommitment(
    uint32_t generation, uint32_t first_epoch)
{
    const auto tree_id{llmq::pq::GetChildKeyTreeId(
        uint256::ONEV, uint256::TWOV, generation, first_epoch)};
    BOOST_REQUIRE(tree_id);
    // A schedule-bound stand-in exposes stale-root relabeling without the
    // production builder's 65,536 scheduled-WOTS key expansions.
    CHashWriter writer{SER_GETHASH, 0};
    writer << std::string{"SYS_PQ_WALLET_SCHEDULE_TEST_V1"}
           << *tree_id << generation << first_epoch;
    llmq::pq::ChildKeyTreeCommitment commitment;
    commitment.generation = generation;
    commitment.first_epoch = first_epoch;
    commitment.tree_id = *tree_id;
    commitment.root = writer.GetHash();
    BOOST_REQUIRE(commitment.IsStructurallyValid());
    return commitment;
}

} // namespace

BOOST_AUTO_TEST_SUITE(wallet_util_tests)

BOOST_AUTO_TEST_CASE(util_ParseISO8601DateTime)
{
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("1970-01-01T00:00:00Z"), 0);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("1960-01-01T00:00:00Z"), 0);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("2000-01-01T00:00:01Z"), 946684801);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("2011-09-30T23:36:17Z"), 1317425777);
    BOOST_CHECK_EQUAL(ParseISO8601DateTime("2100-12-31T23:59:59Z"), 4133980799);
}

BOOST_AUTO_TEST_CASE(wallet_pq_child_commitment_keeps_current_schedule)
{
    for (const int32_t completed_height : {1294, 1295}) {
        int32_t next_height{1294};
        std::size_t reads{0};
        std::vector<llmq::pq::ChildKeyTreeCommitment> built;
        const auto commitment{BuildCurrentPQChildKeyCommitment(
            [&] {
                ++reads;
                return FirstMutablePQEpoch(next_height);
            },
            [&](uint32_t first_epoch) {
                built.push_back(ScheduleBoundTestCommitment(1, first_epoch));
                next_height = completed_height;
                return built.back();
            })};
        BOOST_REQUIRE(commitment);
        BOOST_REQUIRE_EQUAL(built.size(), 1U);
        BOOST_CHECK_EQUAL(reads, 2U);
        BOOST_CHECK_EQUAL(commitment->first_epoch, 0U);
        BOOST_CHECK(*commitment == built.front());
    }
}

BOOST_AUTO_TEST_CASE(wallet_pq_child_commitment_rebuilds_initial_and_rotated_roots)
{
    BOOST_REQUIRE_EQUAL(FirstMutablePQEpoch(1295), 0U);
    BOOST_REQUIRE_EQUAL(FirstMutablePQEpoch(1296), 1U);
    for (const uint32_t generation : {1U, 2U}) {
        int32_t next_height{1295};
        std::size_t reads{0};
        std::vector<llmq::pq::ChildKeyTreeCommitment> built;
        const auto commitment{BuildCurrentPQChildKeyCommitment(
            [&] {
                ++reads;
                return FirstMutablePQEpoch(next_height);
            },
            [&](uint32_t first_epoch) {
                built.push_back(
                    ScheduleBoundTestCommitment(generation, first_epoch));
                next_height = 1296;
                return built.back();
            })};
        BOOST_REQUIRE(commitment);
        BOOST_REQUIRE_EQUAL(built.size(), 2U);
        BOOST_CHECK_EQUAL(reads, 3U);
        BOOST_CHECK_EQUAL(built.front().first_epoch, 0U);
        BOOST_CHECK_EQUAL(built.back().first_epoch, 1U);
        BOOST_CHECK_EQUAL(commitment->generation, generation);
        BOOST_CHECK(built.front().tree_id != built.back().tree_id);
        BOOST_CHECK(built.front().root != built.back().root);
        BOOST_CHECK(*commitment == built.back());
    }
}

BOOST_AUTO_TEST_CASE(wallet_pq_child_commitment_bounds_cutoff_rebuilds)
{
    int32_t next_height{1295};
    std::size_t reads{0};
    std::vector<llmq::pq::ChildKeyTreeCommitment> built;
    const auto commitment{BuildCurrentPQChildKeyCommitment(
        [&] {
            ++reads;
            return FirstMutablePQEpoch(next_height);
        },
        [&](uint32_t first_epoch) {
            built.push_back(ScheduleBoundTestCommitment(1, first_epoch));
            BOOST_REQUIRE_LE(built.size(), 2U);
            next_height = built.size() == 1 ? 1296 : 1584;
            return built.back();
        })};
    BOOST_CHECK(!commitment);
    BOOST_REQUIRE_EQUAL(built.size(), 2U);
    BOOST_CHECK_EQUAL(reads, 3U);
    BOOST_CHECK_EQUAL(built.front().first_epoch, 0U);
    BOOST_CHECK_EQUAL(built.back().first_epoch, 1U);
    BOOST_CHECK_EQUAL(FirstMutablePQEpoch(next_height), 2U);
}

BOOST_AUTO_TEST_CASE(wallet_pq_child_commitment_rebuilds_after_cutoff_rewind)
{
    int32_t next_height{1296};
    std::vector<llmq::pq::ChildKeyTreeCommitment> built;
    const auto commitment{BuildCurrentPQChildKeyCommitment(
        [&] { return FirstMutablePQEpoch(next_height); },
        [&](uint32_t first_epoch) {
            built.push_back(ScheduleBoundTestCommitment(2, first_epoch));
            next_height = 1295;
            return built.back();
        })};
    BOOST_REQUIRE(commitment);
    BOOST_REQUIRE_EQUAL(built.size(), 2U);
    BOOST_CHECK_EQUAL(built.front().first_epoch, 1U);
    BOOST_CHECK_EQUAL(built.back().first_epoch, 0U);
    BOOST_CHECK(built.front().tree_id != built.back().tree_id);
    BOOST_CHECK(built.front().root != built.back().root);
    BOOST_CHECK(*commitment == built.back());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
