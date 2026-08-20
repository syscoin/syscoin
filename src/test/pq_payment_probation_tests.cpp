// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_payment_probation.h>

#include <protocol.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

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

void SetBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

void ClearBit(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] &=
        static_cast<uint8_t>(~(uint8_t{1} << (member % 8)));
}

PQPaymentAuditReceiptIdentity Receipt(uint32_t epoch, uint64_t tag)
{
    return {epoch, static_cast<int32_t>(epoch * PQ_EPOCH_BLOCKS + 100),
            NonNullHash(100'000 + tag)};
}

PQPaymentProbationTransitionInput Input(uint32_t epoch,
                                        uint64_t receipt_tag,
                                        std::size_t observed_count)
{
    PQPaymentProbationTransitionInput input;
    input.receipt = Receipt(epoch, receipt_tag);
    input.roster_valid_members.fill(0xff);
    for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
        input.frozen_roster[member] = NonNullHash(1 + member);
        input.existing_pro_tx_hashes.push_back(input.frozen_roster[member]);
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

PQPaymentProbationState State(
    std::initializer_list<PQPaymentProbationEntry> entries)
{
    PQPaymentProbationState state;
    state.entries.assign(entries.begin(), entries.end());
    std::sort(state.entries.begin(), state.entries.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    BOOST_REQUIRE(state.IsStructurallyValid());
    return state;
}

bool Contains(std::span<const uint256> values, const uint256& value)
{
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_probation_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(two_conclusive_misses_withhold_and_cap)
{
    auto first_input{Input(/*epoch=*/1, /*receipt_tag=*/1,
                           PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};
    PQPaymentProbationError error{PQPaymentProbationError::INVALID_STATE};
    const auto first{ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, first_input, &error)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(error == PQPaymentProbationError::NONE);
    BOOST_CHECK(first->conclusive);
    BOOST_CHECK_EQUAL(first->effective_observed_count, 300U);
    BOOST_CHECK_EQUAL(first->state.entries.size(), 100U);
    BOOST_CHECK_EQUAL(first->state.MissCount(first_input.frozen_roster[300]),
                      1U);
    BOOST_CHECK(!first->state.IsPaymentWithheld(
        first_input.frozen_roster[300]));

    auto second_input{first_input};
    second_input.receipt = Receipt(2, 2);
    const auto second{ApplyPQPaymentProbationTransition(
        first->state, second_input, &error)};
    BOOST_REQUIRE(second);
    BOOST_CHECK(second->conclusive);
    BOOST_CHECK_EQUAL(second->state.entries.size(), 100U);
    BOOST_CHECK_EQUAL(second->state.MissCount(second_input.frozen_roster[300]),
                      2U);
    BOOST_CHECK(second->state.IsPaymentWithheld(
        second_input.frozen_roster[300]));

    auto third_input{second_input};
    third_input.receipt = Receipt(3, 3);
    const auto third{ApplyPQPaymentProbationTransition(
        second->state, third_input, &error)};
    BOOST_REQUIRE(third);
    BOOST_CHECK_EQUAL(third->state.MissCount(third_input.frozen_roster[300]),
                      2U);
    BOOST_CHECK(third->undo.changes.empty());
}

BOOST_AUTO_TEST_CASE(positive_recovers_even_when_audit_is_inconclusive)
{
    auto input{Input(/*epoch=*/4, /*receipt_tag=*/4,
                     /*observed_count=*/1)};
    const auto withheld{input.frozen_roster[0]};
    const auto missed_once{input.frozen_roster[350]};
    auto previous{State({{withheld, 2}, {missed_once, 1}})};

    // The positive member is deliberately not current-valid. Its collateral
    // still exists, so transient validity fields cannot prevent recovery.
    input.current_valid_pro_tx_hashes.erase(
        std::lower_bound(input.current_valid_pro_tx_hashes.begin(),
                         input.current_valid_pro_tx_hashes.end(), withheld));
    BOOST_REQUIRE(input.IsStructurallyValid());

    const auto result{
        ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(!result->conclusive);
    BOOST_CHECK_EQUAL(result->effective_observed_count, 0U);
    BOOST_REQUIRE_EQUAL(result->recovered_pro_tx_hashes.size(), 1U);
    BOOST_CHECK(result->recovered_pro_tx_hashes.front() == withheld);
    BOOST_CHECK_EQUAL(result->state.MissCount(withheld), 0U);
    BOOST_CHECK_EQUAL(
        result->state.PaymentEligibleSinceHeight(withheld),
        input.receipt.carrier_height);
    BOOST_CHECK_EQUAL(result->state.MissCount(missed_once), 1U);
}

BOOST_AUTO_TEST_CASE(conclusive_gate_uses_observed_members_still_current_valid)
{
    auto input{Input(/*epoch=*/5, /*receipt_tag=*/5,
                     PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};
    const auto observed_but_not_current{input.frozen_roster[0]};
    input.current_valid_pro_tx_hashes.erase(
        std::lower_bound(input.current_valid_pro_tx_hashes.begin(),
                         input.current_valid_pro_tx_hashes.end(),
                         observed_but_not_current));
    BOOST_REQUIRE(input.IsStructurallyValid());

    const auto inconclusive{ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, input)};
    BOOST_REQUIRE(inconclusive);
    BOOST_CHECK(!inconclusive->conclusive);
    BOOST_CHECK_EQUAL(inconclusive->effective_observed_count, 299U);
    BOOST_CHECK(inconclusive->state.entries.empty());

    auto next{input};
    next.receipt = Receipt(6, 6);
    next.current_valid_pro_tx_hashes.push_back(observed_but_not_current);
    std::sort(next.current_valid_pro_tx_hashes.begin(),
              next.current_valid_pro_tx_hashes.end());
    BOOST_REQUIRE(next.IsStructurallyValid());
    const auto conclusive{
        ApplyPQPaymentProbationTransition(inconclusive->state, next)};
    BOOST_REQUIRE(conclusive);
    BOOST_CHECK(conclusive->conclusive);
    BOOST_CHECK_EQUAL(conclusive->state.entries.size(), 100U);
}

BOOST_AUTO_TEST_CASE(nonexistent_collaterals_are_pruned_without_recovery)
{
    auto input{Input(/*epoch=*/7, /*receipt_tag=*/7,
                     /*observed_count=*/0)};
    const uint256 removed{NonNullHash(50'000)};
    const uint256 survivor{input.frozen_roster[350]};
    auto previous{State({{removed, 2}, {survivor, 1}})};

    const auto result{ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(result);
    BOOST_CHECK(!result->conclusive);
    BOOST_REQUIRE_EQUAL(result->pruned_pro_tx_hashes.size(), 1U);
    BOOST_CHECK(result->pruned_pro_tx_hashes.front() == removed);
    BOOST_CHECK(result->recovered_pro_tx_hashes.empty());
    BOOST_CHECK_EQUAL(result->state.MissCount(removed), 0U);
    BOOST_CHECK_EQUAL(result->state.MissCount(survivor), 1U);
}

BOOST_AUTO_TEST_CASE(maximal_prune_and_new_misses_have_reversible_wide_diff)
{
    PQPaymentProbationState previous;
    previous.entries.reserve(MAX_PQ_PAYMENT_PROBATION_ENTRIES);
    for (std::size_t index{0};
         index < MAX_PQ_PAYMENT_PROBATION_ENTRIES; ++index) {
        previous.entries.push_back({
            NonNullHash(1'000'000 + index), 1, -1});
    }
    std::sort(previous.entries.begin(), previous.entries.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    BOOST_REQUIRE(previous.IsStructurallyValid());

    auto input{Input(/*epoch=*/100, /*receipt_tag=*/100,
                     PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};
    const auto applied{ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(applied);
    BOOST_CHECK_EQUAL(applied->state.entries.size(),
                      QUORUM_SIZE -
                          PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS);
    BOOST_CHECK_EQUAL(applied->undo.changes.size(),
                      MAX_PQ_PAYMENT_PROBATION_ENTRIES +
                          QUORUM_SIZE -
                          PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS);
    BOOST_CHECK_GT(applied->undo.changes.size(),
                   std::numeric_limits<uint16_t>::max());

    CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
    encoded << applied->undo;
    PQPaymentProbationDiff decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded == applied->undo);
    const auto restored{UndoPQPaymentProbationTransition(
        applied->state, decoded)};
    BOOST_REQUIRE(restored);
    BOOST_CHECK(*restored == previous);
}

BOOST_AUTO_TEST_CASE(receipts_are_exact_and_strictly_monotonic)
{
    auto input{Input(/*epoch=*/10, /*receipt_tag=*/10,
                     /*observed_count=*/0)};
    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    const auto accepted{ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, input, &error)};
    BOOST_REQUIRE(accepted);

    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        accepted->state, input, &error));
    BOOST_CHECK(error == PQPaymentProbationError::DUPLICATE_RECEIPT);

    auto conflict{input};
    conflict.receipt.receipt_id = NonNullHash(123'456);
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        accepted->state, conflict, &error));
    BOOST_CHECK(error == PQPaymentProbationError::CONFLICTING_RECEIPT);

    auto old{input};
    old.receipt = Receipt(9, 23'457);
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        accepted->state, old, &error));
    BOOST_CHECK(error == PQPaymentProbationError::OUT_OF_ORDER_RECEIPT);

    auto newer{input};
    newer.receipt = Receipt(12, 23'458);
    BOOST_CHECK(ApplyPQPaymentProbationTransition(
        accepted->state, newer, &error));
    BOOST_CHECK(error == PQPaymentProbationError::NONE);
}

BOOST_AUTO_TEST_CASE(diff_undo_restores_pruning_recovery_and_misses)
{
    auto input{Input(/*epoch=*/21, /*receipt_tag=*/21,
                     PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};
    const uint256 recovered{input.frozen_roster[0]};
    const uint256 removed{NonNullHash(60'000)};
    auto previous{State({{recovered, 2}, {removed, 1}})};
    previous.cursor = {1, Receipt(20, 20)};
    BOOST_REQUIRE(previous.IsStructurallyValid());

    const auto applied{ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(applied);
    BOOST_CHECK(applied->state != previous);
    BOOST_CHECK(applied->undo.IsStructurallyValid());
    const auto undone{UndoPQPaymentProbationTransition(
        applied->state, applied->undo)};
    BOOST_REQUIRE(undone);
    BOOST_CHECK(*undone == previous);

    auto wrong_tip{applied->state};
    wrong_tip.cursor.receipt.receipt_id = NonNullHash(999'999);
    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    BOOST_CHECK(!UndoPQPaymentProbationTransition(
        wrong_tip, applied->undo, &error));
    BOOST_CHECK(error == PQPaymentProbationError::UNDO_MISMATCH);

    auto drifted_tip{applied->state};
    BOOST_REQUIRE(!drifted_tip.entries.empty());
    drifted_tip.entries.back().consecutive_misses = 2;
    BOOST_REQUIRE(drifted_tip.IsStructurallyValid());
    BOOST_CHECK(!UndoPQPaymentProbationTransition(
        drifted_tip, applied->undo, &error));
    BOOST_CHECK(error == PQPaymentProbationError::UNDO_MISMATCH);
}

BOOST_AUTO_TEST_CASE(state_and_diff_serialization_are_versioned_and_canonical)
{
    auto input{Input(/*epoch=*/31, /*receipt_tag=*/31,
                     PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};
    const auto applied{ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, input)};
    BOOST_REQUIRE(applied);

    CDataStream state_stream{SER_NETWORK, PROTOCOL_VERSION};
    state_stream << applied->state;
    PQPaymentProbationState decoded_state;
    state_stream >> decoded_state;
    BOOST_CHECK(decoded_state == applied->state);
    BOOST_CHECK(state_stream.empty());

    CDataStream diff_stream{SER_NETWORK, PROTOCOL_VERSION};
    diff_stream << applied->undo;
    PQPaymentProbationDiff decoded_diff;
    diff_stream >> decoded_diff;
    BOOST_CHECK(decoded_diff == applied->undo);
    BOOST_CHECK(diff_stream.empty());

    CDataStream oversized_diff{SER_NETWORK, PROTOCOL_VERSION};
    oversized_diff << applied->undo.version
                   << applied->undo.previous_cursor
                   << applied->undo.applied_receipt
                   << applied->undo.previous_state_hash
                   << applied->undo.applied_state_hash
                   << std::numeric_limits<uint32_t>::max();
    PQPaymentProbationDiff rejected_diff;
    BOOST_CHECK_THROW(oversized_diff >> rejected_diff,
                      std::ios_base::failure);

    auto unsorted{applied->state};
    std::swap(unsorted.entries[0], unsorted.entries[1]);
    BOOST_CHECK(!unsorted.IsStructurallyValid());
    CDataStream invalid_stream{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK_THROW(invalid_stream << unsorted, std::ios_base::failure);

    auto bad_version{applied->state};
    bad_version.version = PQ_PAYMENT_PROBATION_STATE_VERSION - 1;
    BOOST_CHECK(!bad_version.IsStructurallyValid());

    auto noncanonical_cursor{applied->state};
    noncanonical_cursor.cursor.has_receipt = 0;
    BOOST_CHECK(!noncanonical_cursor.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(rejects_malformed_rosters_bitmaps_and_membership_sets)
{
    auto input{Input(/*epoch=*/41, /*receipt_tag=*/41,
                     PQ_PAYMENT_AUDIT_CONCLUSIVE_MEMBERS)};

    auto duplicate_roster{input};
    duplicate_roster.frozen_roster[1] = duplicate_roster.frozen_roster[0];
    BOOST_CHECK(!duplicate_roster.IsStructurallyValid());
    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, duplicate_roster, &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_ROSTER);

    auto observed_invalid{input};
    ClearBit(observed_invalid.roster_valid_members, 0);
    BOOST_CHECK(!observed_invalid.IsStructurallyValid());
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, observed_invalid, &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_BITMAP);

    auto too_few_valid{input};
    for (std::size_t member{299}; member < QUORUM_SIZE; ++member) {
        ClearBit(too_few_valid.roster_valid_members, member);
        ClearBit(too_few_valid.observed_members, member);
    }
    BOOST_CHECK(!too_few_valid.IsStructurallyValid());

    auto unsorted_existing{input};
    std::swap(unsorted_existing.existing_pro_tx_hashes[0],
              unsorted_existing.existing_pro_tx_hashes[1]);
    BOOST_CHECK(!unsorted_existing.IsStructurallyValid());
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, unsorted_existing, &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_COLLATERAL_SET);

    auto valid_not_existing{input};
    valid_not_existing.current_valid_pro_tx_hashes.push_back(
        NonNullHash(70'000));
    std::sort(valid_not_existing.current_valid_pro_tx_hashes.begin(),
              valid_not_existing.current_valid_pro_tx_hashes.end());
    BOOST_CHECK(!valid_not_existing.IsStructurallyValid());
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, valid_not_existing, &error));
    BOOST_CHECK(error ==
                PQPaymentProbationError::INVALID_CURRENT_VALID_SET);

    auto null_receipt{input};
    null_receipt.receipt.receipt_id.SetNull();
    BOOST_CHECK(!null_receipt.IsStructurallyValid());
    BOOST_CHECK(!ApplyPQPaymentProbationTransition(
        PQPaymentProbationState{}, null_receipt, &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_RECEIPT);
}

BOOST_AUTO_TEST_CASE(payee_selection_filters_probation_but_never_all_to_none)
{
    const std::vector<uint256> queue{
        NonNullHash(93), NonNullHash(91), NonNullHash(92)};
    auto partial{State({{queue[0], 2}, {queue[2], 2}})};
    const auto selected{SelectPQPaymentPayee(partial, queue)};
    BOOST_REQUIRE(selected);
    BOOST_REQUIRE(selected->pro_tx_hash);
    BOOST_CHECK(*selected->pro_tx_hash == queue[1]);
    BOOST_CHECK(!selected->used_all_probated_fallback);

    auto all{State({{queue[0], 2}, {queue[1], 2}, {queue[2], 2}})};
    const auto fallback{SelectPQPaymentPayee(all, queue)};
    BOOST_REQUIRE(fallback);
    BOOST_REQUIRE(fallback->pro_tx_hash);
    BOOST_CHECK(*fallback->pro_tx_hash == queue.front());
    BOOST_CHECK(fallback->used_all_probated_fallback);

    const auto empty{SelectPQPaymentPayee(
        all, std::span<const uint256>{})};
    BOOST_REQUIRE(empty);
    BOOST_CHECK(!empty->pro_tx_hash);
    BOOST_CHECK(!empty->used_all_probated_fallback);

    std::vector<uint256> duplicate_queue{queue[0], queue[0]};
    PQPaymentProbationError error{PQPaymentProbationError::NONE};
    BOOST_CHECK(!SelectPQPaymentPayee(all, duplicate_queue, &error));
    BOOST_CHECK(error == PQPaymentProbationError::INVALID_PAYMENT_QUEUE);
}

BOOST_AUTO_TEST_CASE(recovery_output_is_sorted_for_queue_reentry)
{
    auto input{Input(/*epoch=*/51, /*receipt_tag=*/51,
                     /*observed_count=*/3)};
    auto previous{State({{input.frozen_roster[2], 2},
                         {input.frozen_roster[0], 2},
                         {input.frozen_roster[1], 2}})};
    const auto result{ApplyPQPaymentProbationTransition(previous, input)};
    BOOST_REQUIRE(result);
    BOOST_REQUIRE_EQUAL(result->recovered_pro_tx_hashes.size(), 3U);
    BOOST_CHECK(std::is_sorted(result->recovered_pro_tx_hashes.begin(),
                               result->recovered_pro_tx_hashes.end()));
    for (std::size_t member{0}; member < 3; ++member) {
        BOOST_CHECK(Contains(result->recovered_pro_tx_hashes,
                             input.frozen_roster[member]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
