// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_schedule.h>
#include <llmq/pq_payment_audit.h>

#include <algorithm>
#include <cstdint>
#include <limits>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

BOOST_AUTO_TEST_SUITE(pq_chainlock_schedule_tests)

BOOST_AUTO_TEST_CASE(profile_and_origin_validation)
{
    ChainLockScheduleConfig config{.epoch_origin = 1440};
    BOOST_CHECK(config.IsValid());

    config.epoch_origin = -1;
    BOOST_CHECK(!config.IsValid());
    config.epoch_origin = 1439;
    BOOST_CHECK(!config.IsValid());
    config.epoch_origin = 2880;
    BOOST_CHECK(config.IsValid());

    auto wrong = config;
    wrong.epoch_blocks++;
    BOOST_CHECK(!wrong.IsValid());
    wrong = config;
    wrong.chainlock_period++;
    BOOST_CHECK(!wrong.IsValid());
    wrong = config;
    wrong.sign_lag++;
    BOOST_CHECK(!wrong.IsValid());
    wrong = config;
    wrong.active_epochs++;
    BOOST_CHECK(!wrong.IsValid());
}

BOOST_AUTO_TEST_CASE(epoch_boundaries_and_four_epoch_warmup)
{
    const ChainLockScheduleConfig config{.epoch_origin = 1440};
    BOOST_CHECK(!EpochForHeight(config, -1));
    BOOST_CHECK(!EpochForHeight(config, 1439));
    BOOST_CHECK_EQUAL(*EpochForHeight(config, 1440), 0U);
    BOOST_CHECK_EQUAL(*EpochForHeight(config, 1727), 0U);
    BOOST_CHECK_EQUAL(*EpochForHeight(config, 1728), 1U);
    BOOST_CHECK_EQUAL(*EpochBaseHeight(config, 0), 1440);
    BOOST_CHECK_EQUAL(*EpochBaseHeight(config, 3), 2304);
    BOOST_CHECK_EQUAL(*EpochEndHeightExclusive(config, 3), 2592);

    BOOST_CHECK(!ActiveEpochsAtHeight(config, 2303));
    const auto first_active{ActiveEpochsAtHeight(config, 2304)};
    BOOST_REQUIRE(first_active);
    for (std::size_t slot{0}; slot < first_active->size(); ++slot) {
        BOOST_CHECK_EQUAL((*first_active)[slot].epoch, slot);
        BOOST_CHECK_EQUAL((*first_active)[slot].base_height,
                          1440 + static_cast<int32_t>(slot * PQ_EPOCH_BLOCKS));
    }

    const auto rotated{ActiveEpochsAtHeight(config, 2592)};
    BOOST_REQUIRE(rotated);
    for (std::size_t slot{0}; slot < rotated->size(); ++slot) {
        BOOST_CHECK_EQUAL((*rotated)[slot].epoch, slot + 1);
    }
}

BOOST_AUTO_TEST_CASE(cadence_and_sign_lag_boundaries)
{
    const ChainLockScheduleConfig config{.epoch_origin = 1440};
    BOOST_CHECK(!IsChainLockCadenceHeight(config, -5));
    BOOST_CHECK(!IsChainLockCadenceHeight(config, 1435));
    BOOST_CHECK(IsChainLockCadenceHeight(config, 1440));
    BOOST_CHECK(IsChainLockCadenceHeight(config, 2305));

    // Epoch three starts at 2304; the first absolute five-block target is 2305.
    BOOST_CHECK(!IsEligibleChainLockTarget(config, 2300));
    BOOST_CHECK(!IsEligibleChainLockTarget(config, 2304));
    BOOST_CHECK(IsEligibleChainLockTarget(config, 2305));
    BOOST_CHECK_EQUAL(*SigningHeightForTarget(config, 2305), 2310);
    BOOST_CHECK_EQUAL(*TargetHeightForSigningHeight(config, 2310), 2305);
    BOOST_CHECK(!TargetHeightForSigningHeight(config, 2309));
}

BOOST_AUTO_TEST_CASE(next_target_is_the_unique_eligible_successor)
{
    const ChainLockScheduleConfig config{.epoch_origin = 1440};
    BOOST_CHECK_EQUAL(*NextEligibleChainLockTargetHeight(config, -1), 2305);
    BOOST_CHECK_EQUAL(*NextEligibleChainLockTargetHeight(config, 2304), 2305);
    BOOST_CHECK_EQUAL(*NextEligibleChainLockTargetHeight(config, 2305), 2310);
    BOOST_CHECK_EQUAL(*NextEligibleChainLockTargetHeight(config, 2306), 2310);
    BOOST_CHECK(!NextEligibleChainLockTargetHeight(config, -2));

    auto invalid{config};
    ++invalid.epoch_origin;
    BOOST_CHECK(!NextEligibleChainLockTargetHeight(invalid, 2305));
}

BOOST_AUTO_TEST_CASE(current_window_recovers_without_skipping_the_wire_predecessor)
{
    const ChainLockScheduleConfig config{.epoch_origin = 0};

    BOOST_CHECK(!LatestEligibleChainLockTargetHeight(config, 869));
    BOOST_CHECK_EQUAL(*LatestEligibleChainLockTargetHeight(config, 870), 865);
    BOOST_CHECK_EQUAL(*LatestEligibleChainLockTargetHeight(config, 884), 875);
    BOOST_CHECK_EQUAL(*LatestEligibleChainLockTargetHeight(config, 885), 880);

    const auto exact{CurrentChainLockSigningWindow(
        config, /*durable_predecessor_height=*/864, /*tip_height=*/870)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK_EQUAL(exact->target_height, 865);
    BOOST_CHECK_EQUAL(exact->declared_predecessor_height, 864);

    const auto recovered{CurrentChainLockSigningWindow(
        config, /*durable_predecessor_height=*/864, /*tip_height=*/885)};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK_EQUAL(recovered->target_height, 880);
    BOOST_CHECK_EQUAL(recovered->declared_predecessor_height, 875);
    BOOST_CHECK_EQUAL(
        *NextEligibleChainLockTargetHeight(
            config, recovered->declared_predecessor_height),
        recovered->target_height);

    BOOST_CHECK(!CurrentChainLockSigningWindow(
        config, /*durable_predecessor_height=*/880, /*tip_height=*/885));
}

BOOST_AUTO_TEST_CASE(cutoff_and_expiry_are_checked)
{
    const ChainLockScheduleConfig config{.epoch_origin = 0};
    BOOST_CHECK_EQUAL(*EpochBaseHeight(config, 5), 1440);
    BOOST_CHECK_EQUAL(*RegistrationCutoffHeight(config, 5, 0), 1440);
    BOOST_CHECK_EQUAL(*RegistrationCutoffHeight(config, 5, 288), 1152);
    BOOST_CHECK(IsRegistrationCutoffHeight(config, 288, 1152));
    BOOST_CHECK(!IsRegistrationCutoffHeight(config, 288, 1151));
    BOOST_CHECK(!IsRegistrationCutoffHeight(config, 288, 1153));
    BOOST_CHECK(IsRegistrationCutoffHeight(config, 288, 0));
    BOOST_CHECK(!IsRegistrationCutoffHeight(config, 288, -1));
    BOOST_CHECK(!IsRegistrationCutoffHeight(
        config, 288, std::numeric_limits<int32_t>::max()));
    BOOST_CHECK(IsBeforeRegistrationCutoff(config, 5, 288, 1151));
    BOOST_CHECK(!IsBeforeRegistrationCutoff(config, 5, 288, 1152));
    BOOST_CHECK(!IsBeforeRegistrationCutoff(config, 5, 288, 1153));
    BOOST_CHECK(!IsBeforeRegistrationCutoff(config, 5, 288, -1));
    BOOST_CHECK_EQUAL(*RegistrationCutoffHeight(config, 5, 1440), 0);
    BOOST_CHECK(!IsBeforeRegistrationCutoff(config, 5, 1440, 0));
    BOOST_CHECK(!RegistrationCutoffHeight(config, 5, 1441));
    BOOST_CHECK(!RegistrationCutoffHeight(config, 0, 1));
    BOOST_CHECK_EQUAL(*QuorumExpiryHeightExclusive(config, 5), 2592);
}

BOOST_AUTO_TEST_CASE(exact_child_lifetime_usage_bound)
{
    const ChainLockScheduleConfig config{.epoch_origin = 0};

    const auto early{EligibleTargetsForEpoch(config, 0)};
    BOOST_REQUIRE(early);
    BOOST_CHECK_EQUAL(early->first_height, 865);
    BOOST_CHECK_EQUAL(early->last_height, 1150);
    BOOST_CHECK_EQUAL(early->count, 58U);

    const auto maximum{EligibleTargetsForEpoch(config, 3)};
    BOOST_REQUIRE(maximum);
    BOOST_CHECK_EQUAL(maximum->first_height, 865);
    BOOST_CHECK_EQUAL(maximum->last_height, 2015);
    BOOST_CHECK_EQUAL(maximum->count, 231U);

    const auto phase_shorter{EligibleTargetsForEpoch(config, 4)};
    BOOST_REQUIRE(phase_shorter);
    BOOST_CHECK_EQUAL(phase_shorter->first_height, 1155);
    BOOST_CHECK_EQUAL(phase_shorter->last_height, 2300);
    BOOST_CHECK_EQUAL(phase_shorter->count, 230U);

    uint16_t observed_max{0};
    for (uint32_t epoch{0}; epoch < 10'000; ++epoch) {
        const auto span{EligibleTargetsForEpoch(config, epoch)};
        BOOST_REQUIRE(span);
        observed_max = std::max(observed_max, span->count);
        BOOST_CHECK_LE(span->count, PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD);
        BOOST_CHECK_LE(span->count, SCHEDULED_WOTS_USAGE_CAP);

        uint16_t enumerated{0};
        for (int32_t height{span->first_height}; height <= span->last_height;
             height += PQ_CL_PERIOD) {
            BOOST_CHECK(IsEligibleChainLockTarget(config, height));
            BOOST_CHECK(IsEpochActiveForTarget(config, epoch, height));
            ++enumerated;
        }
        BOOST_CHECK_EQUAL(enumerated, span->count);
        BOOST_CHECK(!IsEpochActiveForTarget(config, epoch, span->last_height + PQ_CL_PERIOD));
    }
    BOOST_CHECK_EQUAL(observed_max, 231U);
}

BOOST_AUTO_TEST_CASE(chainlock_leaf_mapping_has_exact_scheduled_boundaries)
{
    const ChainLockScheduleConfig config{.epoch_origin = 0};

    const auto first{ChainLockLeafIndex(config, /*child_epoch=*/3,
                                        /*target_height=*/865)};
    const auto last{ChainLockLeafIndex(config, /*child_epoch=*/3,
                                       /*target_height=*/2'015)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(static_cast<unsigned>(*first), 0U);
    BOOST_CHECK_EQUAL(static_cast<unsigned>(*last), 230U);

    BOOST_CHECK(!ChainLockLeafIndex(config, 3, 864));
    BOOST_CHECK(!ChainLockLeafIndex(config, 3, 866));
    BOOST_CHECK(!ChainLockLeafIndex(config, 3, 2'020));
    BOOST_CHECK(!ChainLockLeafIndex(config, 2, 2'015));

    auto invalid{config};
    ++invalid.chainlock_period;
    BOOST_CHECK(!ChainLockLeafIndex(invalid, 3, 865));
    BOOST_CHECK(!ChainLockLeafIndex(
        config, std::numeric_limits<uint32_t>::max(), 865));
}

BOOST_AUTO_TEST_CASE(payment_audit_leaf_mapping_uses_full_schedule_and_231_to_234)
{
    const auto chainlock{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock);
    const PaymentAuditScheduleConfig config{
        *chainlock,
        BTCCScheduleConfig{.candidate_origin = 865},
    };
    BOOST_REQUIRE(config.IsValid());
    const auto audit{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(audit);
    BOOST_CHECK_EQUAL(audit->seal_height, 1'370);

    // The seal is in epoch four. Newest-to-oldest active child epochs map to
    // the four purpose-separated audit leaves.
    for (uint32_t distance{0}; distance < ACTIVE_QUORUMS; ++distance) {
        const auto leaf{PaymentAuditLeafIndex(
            config, /*subject_epoch=*/3, audit->seal_height,
            /*child_epoch=*/4 - distance)};
        BOOST_REQUIRE(leaf);
        BOOST_CHECK_EQUAL(
            static_cast<unsigned>(*leaf),
            static_cast<unsigned>(SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE +
                                  distance));
    }
    BOOST_CHECK_EQUAL(SCHEDULED_WOTS_PAYMENT_AUDIT_LEAF_BASE, 231U);
    BOOST_CHECK_EQUAL(SCHEDULED_WOTS_USAGE_CAP - 1, 234U);

    BOOST_CHECK(!PaymentAuditLeafIndex(config, 3, audit->seal_height, 0));
    BOOST_CHECK(!PaymentAuditLeafIndex(config, 3, audit->seal_height, 5));
    BOOST_CHECK(!PaymentAuditLeafIndex(config, 3, audit->seal_height + 5, 4));
    BOOST_CHECK(!PaymentAuditLeafIndex(config, 2, audit->seal_height, 4));
    BOOST_CHECK(!PaymentAuditLeafIndex(
        config, std::numeric_limits<uint32_t>::max(), audit->seal_height, 4));

    auto invalid{config};
    ++invalid.btcc.candidate_origin;
    BOOST_CHECK(!invalid.IsValid());
    BOOST_CHECK(!PaymentAuditLeafIndex(
        invalid, 3, audit->seal_height, 4));
    invalid = config;
    ++invalid.chainlock.active_epochs;
    BOOST_CHECK(!invalid.IsValid());
    BOOST_CHECK(!PaymentAuditLeafIndex(
        invalid, 3, audit->seal_height, 4));
}

BOOST_AUTO_TEST_CASE(overflow_and_signed_height_edges_fail_closed)
{
    const ChainLockScheduleConfig config{.epoch_origin = 0};
    constexpr int32_t MAX_HEIGHT{std::numeric_limits<int32_t>::max()};
    constexpr int32_t LAST_CADENCE{MAX_HEIGHT - MAX_HEIGHT % PQ_CL_PERIOD};

    ChainLockScheduleConfig late_origin{
        .epoch_origin = MAX_HEIGHT - MAX_HEIGHT % static_cast<int32_t>(PQ_EPOCH_ALIGNMENT)};
    BOOST_CHECK(!late_origin.IsValid());
    BOOST_CHECK(!EpochForHeight(late_origin, late_origin.epoch_origin));

    BOOST_CHECK(EpochForHeight(config, MAX_HEIGHT));
    BOOST_CHECK(!EpochBaseHeight(config, std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(!EpochEndHeightExclusive(config, std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(!QuorumExpiryHeightExclusive(config,
                                              std::numeric_limits<uint32_t>::max()));
    BOOST_CHECK(!EligibleTargetsForEpoch(config, std::numeric_limits<uint32_t>::max()));

    BOOST_CHECK(IsEligibleChainLockTarget(config, LAST_CADENCE));
    BOOST_CHECK(!SigningHeightForTarget(config, LAST_CADENCE));
    BOOST_CHECK_EQUAL(
        *NextEligibleChainLockTargetHeight(
            config, LAST_CADENCE - PQ_CL_PERIOD),
        LAST_CADENCE);
    BOOST_CHECK(!NextEligibleChainLockTargetHeight(config, LAST_CADENCE));
    BOOST_CHECK(!NextEligibleChainLockTargetHeight(config, MAX_HEIGHT));
    BOOST_CHECK(IsEligibleChainLockTarget(config, LAST_CADENCE - PQ_CL_PERIOD));
    BOOST_CHECK_EQUAL(*SigningHeightForTarget(config, LAST_CADENCE - PQ_CL_PERIOD),
                      LAST_CADENCE);

    const auto final_active{ActiveEpochsAtHeight(config, LAST_CADENCE - PQ_CL_PERIOD)};
    BOOST_REQUIRE(final_active);
    for (const auto& identity : *final_active) {
        const auto span{EligibleTargetsForEpoch(config, identity.epoch)};
        BOOST_REQUIRE(span);
        BOOST_CHECK_LE(span->first_height, LAST_CADENCE - PQ_CL_PERIOD);
        BOOST_CHECK_GE(span->last_height, LAST_CADENCE - PQ_CL_PERIOD);
        BOOST_CHECK_LE(span->count, PQ_MAX_ELIGIBLE_TARGETS_PER_CHILD);
    }
}

BOOST_AUTO_TEST_SUITE_END()
