// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_btcc.h>

#include <chain.h>
#include <test/util/setup_common.h>

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

struct IndexChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;

    explicit IndexChain(std::size_t count) : hashes(count), indices(count)
    {
        for (std::size_t height{0}; height < count; ++height) {
            hashes[height] = NonNullHash(1000 + height);
            indices[height].nHeight = static_cast<int32_t>(height);
            indices[height].phashBlock = &hashes[height];
            indices[height].pprev = height == 0 ? nullptr : &indices[height - 1];
            indices[height].BuildSkip();
        }
    }

    CBlockIndex& At(std::size_t height) { return indices.at(height); }
    const CBlockIndex& At(std::size_t height) const { return indices.at(height); }
};

BTCCursor Cursor(const IndexChain& chain, int32_t height)
{
    return BTCCursor{
        height,
        chain.At(height).GetBlockHash(),
        chain.At(height).btcpPrevCommitment};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_btcc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(keep_and_advance_are_branch_bound_and_monotonic)
{
    BTCCScheduleConfig config{.candidate_origin = 0};
    BOOST_REQUIRE(config.IsValid());
    IndexChain chain{41};
    chain.At(10).btcpPrevCommitment = NonNullHash(5010);
    chain.At(20).btcpPrevCommitment = NonNullHash(5020);

    BTCCValidationError error{BTCCValidationError::INVALID_CONFIG};
    const BTCCursor null_cursor;
    BOOST_CHECK(ValidateBTCCursorTransition(
        config, chain.At(20), null_cursor, null_cursor, BTCCAdvance::KEEP, &error));
    BOOST_CHECK(error == BTCCValidationError::NONE);

    const BTCCursor first{Cursor(chain, 10)};
    BOOST_CHECK(ValidateBTCCursorTransition(
        config, chain.At(20), null_cursor, first, BTCCAdvance::ADVANCE, &error));

    BOOST_CHECK(ValidateBTCCursorTransition(
        config, chain.At(30), first, first, BTCCAdvance::KEEP, &error));
    const BTCCursor second{Cursor(chain, 20)};
    BOOST_CHECK(ValidateBTCCursorTransition(
        config, chain.At(30), first, second, BTCCAdvance::ADVANCE, &error));

    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), first, first, BTCCAdvance::ADVANCE, &error));
    BOOST_CHECK(error == BTCCValidationError::NON_MONOTONIC_ADVANCE);

    auto unscheduled{second};
    unscheduled.sys_height = 21;
    unscheduled.sys_hash = chain.At(21).GetBlockHash();
    unscheduled.btc_hash = NonNullHash(5021);
    chain.At(21).btcpPrevCommitment = unscheduled.btc_hash;
    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), first, unscheduled, BTCCAdvance::ADVANCE, &error));
    BOOST_CHECK(error == BTCCValidationError::UNSCHEDULED_CANDIDATE);
}

BOOST_AUTO_TEST_CASE(rejects_cursor_substitution_and_bad_previous_state)
{
    BTCCScheduleConfig config{.candidate_origin = 0};
    IndexChain chain{31};
    chain.At(10).btcpPrevCommitment = NonNullHash(6010);
    chain.At(20).btcpPrevCommitment = NonNullHash(6020);
    const BTCCursor previous{Cursor(chain, 10)};
    const BTCCursor accepted{Cursor(chain, 20)};
    BTCCValidationError error{BTCCValidationError::NONE};

    auto wrong_sys{accepted};
    wrong_sys.sys_hash = NonNullHash(9990);
    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), previous, wrong_sys, BTCCAdvance::ADVANCE, &error));
    BOOST_CHECK(error == BTCCValidationError::SYS_HASH_MISMATCH);

    auto wrong_btc{accepted};
    wrong_btc.btc_hash = NonNullHash(9991);
    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), previous, wrong_btc, BTCCAdvance::ADVANCE, &error));
    BOOST_CHECK(error == BTCCValidationError::BTC_HASH_MISMATCH);

    auto stale_previous{previous};
    stale_previous.sys_hash = NonNullHash(9992);
    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), stale_previous, stale_previous,
        BTCCAdvance::KEEP, &error));
    BOOST_CHECK(error == BTCCValidationError::SYS_HASH_MISMATCH);

    BOOST_CHECK(!ValidateBTCCursorTransition(
        config, chain.At(30), previous, accepted, BTCCAdvance::KEEP, &error));
    BOOST_CHECK(error == BTCCValidationError::KEEP_MISMATCH);
}

BOOST_AUTO_TEST_CASE(chainlock_selection_advances_only_at_the_exact_candidate)
{
    BTCCScheduleConfig config{.candidate_origin = 0};
    IndexChain chain{31};
    BTCCValidationError error{BTCCValidationError::INVALID_CONFIG};

    const auto missing_latest{
        SelectBTCCForChainLock(config, chain.At(25), BTCCursor{}, &error)};
    BOOST_REQUIRE(missing_latest);
    BOOST_CHECK(missing_latest->advance == BTCCAdvance::KEEP);
    BOOST_CHECK(missing_latest->cursor.IsNull());
    BOOST_CHECK(error == BTCCValidationError::NONE);

    // Every signer examines one exact height, independent of chain age.
    chain.At(10).btcpPrevCommitment = NonNullHash(8010);
    const auto no_fallback{
        SelectBTCCForChainLock(config, chain.At(25), BTCCursor{}, &error)};
    BOOST_REQUIRE(no_fallback);
    BOOST_CHECK(no_fallback->advance == BTCCAdvance::KEEP);
    BOOST_CHECK(no_fallback->cursor.IsNull());

    chain.At(20).btcpPrevCommitment = NonNullHash(8020);
    const auto selected{
        SelectBTCCForChainLock(config, chain.At(25), BTCCursor{}, &error)};
    BOOST_REQUIRE(selected);
    BOOST_CHECK(selected->advance == BTCCAdvance::KEEP);
    BOOST_CHECK(selected->cursor.IsNull());

    const auto exact{
        SelectBTCCForChainLock(config, chain.At(20), BTCCursor{}, &error)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK(exact->advance == BTCCAdvance::ADVANCE);
    BOOST_CHECK(exact->cursor == Cursor(chain, 20));

    const auto already_accepted{SelectBTCCForChainLock(
        config, chain.At(29), exact->cursor, &error)};
    BOOST_REQUIRE(already_accepted);
    BOOST_CHECK(already_accepted->advance == BTCCAdvance::KEEP);
    BOOST_CHECK(already_accepted->cursor == exact->cursor);
}

BOOST_AUTO_TEST_CASE(chainlock_selection_rejects_a_previous_cursor_off_branch)
{
    BTCCScheduleConfig config{.candidate_origin = 0};
    IndexChain chain{31};
    chain.At(10).btcpPrevCommitment = NonNullHash(9010);
    BTCCursor previous{Cursor(chain, 10)};
    previous.sys_hash = NonNullHash(9999);

    BTCCValidationError error{BTCCValidationError::NONE};
    BOOST_CHECK(!SelectBTCCForChainLock(
        config, chain.At(25), previous, &error));
    BOOST_CHECK(error == BTCCValidationError::SYS_HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(candidate_cadence_and_injection_lag_are_origin_relative)
{
    BTCCScheduleConfig config{.candidate_origin = 7};
    BOOST_REQUIRE(config.IsValid());
    BOOST_CHECK(!IsBTCCCandidateHeight(config, 6));
    BOOST_CHECK(IsBTCCCandidateHeight(config, 7));
    BOOST_CHECK(!IsBTCCCandidateHeight(config, 10));
    BOOST_CHECK(IsBTCCCandidateHeight(config, 17));

    BOOST_CHECK(!BTCCSourceHeightForNEVMInjection(config, 16));
    BOOST_REQUIRE(BTCCSourceHeightForNEVMInjection(config, 17));
    BOOST_CHECK_EQUAL(*BTCCSourceHeightForNEVMInjection(config, 17), 7);
    BOOST_CHECK(!BTCCSourceHeightForNEVMInjection(config, 18));
    BOOST_REQUIRE(BTCCSourceHeightForNEVMInjection(config, 27));
    BOOST_CHECK_EQUAL(*BTCCSourceHeightForNEVMInjection(config, 27), 17);
    BOOST_CHECK(!IsBTCCReceiptCarrierHeight(config, 22));
    BOOST_CHECK(IsBTCCReceiptCarrierHeight(config, 27));

    IndexChain chain{31};
    chain.At(7).btcpPrevCommitment = NonNullHash(10007);
    chain.At(17).btcpPrevCommitment = NonNullHash(10017);
    BTCCValidationError error{BTCCValidationError::INVALID_CONFIG};

    const auto before_origin{
        SelectBTCCForChainLock(config, chain.At(6), BTCCursor{}, &error)};
    BOOST_REQUIRE(before_origin);
    BOOST_CHECK(before_origin->advance == BTCCAdvance::KEEP);

    const auto before_first_candidate{
        SelectBTCCForChainLock(config, chain.At(16), BTCCursor{}, &error)};
    BOOST_REQUIRE(before_first_candidate);
    BOOST_CHECK(before_first_candidate->advance == BTCCAdvance::KEEP);
    BOOST_CHECK(before_first_candidate->cursor.IsNull());

    const auto first{
        SelectBTCCForChainLock(config, chain.At(7), BTCCursor{}, &error)};
    BOOST_REQUIRE(first);
    BOOST_CHECK(first->advance == BTCCAdvance::ADVANCE);
    BOOST_CHECK(first->cursor == Cursor(chain, 7));

    const auto second{
        SelectBTCCForChainLock(config, chain.At(17), first->cursor, &error)};
    BOOST_REQUIRE(second);
    BOOST_CHECK(second->advance == BTCCAdvance::ADVANCE);
    BOOST_CHECK(second->cursor == Cursor(chain, 17));

}

BOOST_AUTO_TEST_CASE(candidate_derivation_tracks_the_connected_reorg_branch)
{
    BTCCScheduleConfig config{.candidate_origin = 0};
    IndexChain old_branch{21};
    IndexChain new_branch{21};
    old_branch.hashes[10] = NonNullHash(11010);
    new_branch.hashes[10] = NonNullHash(12010);
    old_branch.hashes[20] = NonNullHash(11020);
    new_branch.hashes[20] = NonNullHash(12020);
    old_branch.At(10).btcpPrevCommitment = NonNullHash(13010);
    new_branch.At(10).btcpPrevCommitment = NonNullHash(14010);
    old_branch.At(20).btcpPrevCommitment = NonNullHash(13020);
    new_branch.At(20).btcpPrevCommitment = NonNullHash(14020);

    BTCCValidationError error{BTCCValidationError::NONE};
    const auto old_candidate{SelectBTCCForChainLock(
        config, old_branch.At(20), BTCCursor{}, &error)};
    const auto new_candidate{SelectBTCCForChainLock(
        config, new_branch.At(20), BTCCursor{}, &error)};
    BOOST_REQUIRE(old_candidate);
    BOOST_REQUIRE(new_candidate);
    BOOST_CHECK(old_candidate->cursor.sys_hash != new_candidate->cursor.sys_hash);
    BOOST_CHECK(old_candidate->cursor.btc_hash != new_candidate->cursor.btc_hash);

    const BTCCursor old_cursor{Cursor(old_branch, 10)};
    BOOST_CHECK(!SelectBTCCForChainLock(
        config, new_branch.At(20), old_cursor, &error));
    BOOST_CHECK(error == BTCCValidationError::SYS_HASH_MISMATCH);
}

BOOST_AUTO_TEST_CASE(schedule_rejects_lag_overflow_at_height_limit)
{
    BTCCScheduleConfig last_valid{
        .candidate_origin = std::numeric_limits<int32_t>::max() -
                            static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    BOOST_CHECK(last_valid.IsValid());

    BTCCScheduleConfig overflowing{last_valid};
    ++overflowing.candidate_origin;
    BOOST_CHECK(!overflowing.IsValid());
    BOOST_CHECK(!IsBTCCCandidateHeight(overflowing,
                                       overflowing.candidate_origin));
}

BOOST_AUTO_TEST_CASE(receipt_wire_format_and_null_form_are_canonical)
{
    BTCCReceipt receipt;
    BOOST_CHECK(receipt.IsNull());
    BOOST_CHECK(receipt.IsStructurallyValid());
    BOOST_CHECK_EQUAL(::GetSerializeSize(receipt, PROTOCOL_VERSION),
                      BTCCReceipt::WIRE_SIZE);

    receipt.chainlock_target_height = 870;
    BOOST_CHECK(!receipt.IsNull());
    BOOST_CHECK(!receipt.IsStructurallyValid());

    receipt.chainlock_target_hash = NonNullHash(20001);
    receipt.chainlock_logical_id = NonNullHash(20002);
    receipt.accepted_cursor = BTCCursor{
        870, NonNullHash(20003), NonNullHash(20004)};
    BOOST_CHECK(receipt.IsStructurallyValid());
    BOOST_CHECK_EQUAL(::GetSerializeSize(receipt, PROTOCOL_VERSION),
                      BTCCReceipt::WIRE_SIZE);

    receipt.version = PQ_BTCC_RECEIPT_VERSION + 1;
    BOOST_CHECK(!receipt.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(receipt_target_and_cursor_are_bound_to_carrier_branch)
{
    const auto chainlock_schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock_schedule);
    const BTCCScheduleConfig config{.candidate_origin = 0};
    constexpr int32_t ACTIVATION_PREDECESSOR_HEIGHT{869};
    const BTCCReceiptState previous;
    IndexChain chain{881};
    chain.At(870).btcpPrevCommitment = NonNullHash(22001);

    BTCCReceipt receipt;
    receipt.chainlock_target_height = 870;
    receipt.chainlock_target_hash = chain.At(870).GetBlockHash();
    receipt.chainlock_logical_id = NonNullHash(22002);
    receipt.accepted_cursor = Cursor(chain, 870);
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    BOOST_CHECK(ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, receipt));

    auto wrong_target{receipt};
    wrong_target.chainlock_target_hash = NonNullHash(22003);
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, wrong_target));

    auto wrong_sys{receipt};
    wrong_sys.accepted_cursor.sys_hash = NonNullHash(22004);
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, wrong_sys));

    auto wrong_btc{receipt};
    wrong_btc.accepted_cursor.btc_hash = NonNullHash(22005);
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, wrong_btc));

    auto unscheduled{receipt};
    unscheduled.accepted_cursor.sys_height = 871;
    unscheduled.accepted_cursor.sys_hash = chain.At(871).GetBlockHash();
    unscheduled.accepted_cursor.btc_hash = NonNullHash(22006);
    chain.At(871).btcpPrevCommitment = unscheduled.accepted_cursor.btc_hash;
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, unscheduled));

    auto stale_slot{receipt};
    stale_slot.chainlock_target_height = 860;
    stale_slot.chainlock_target_hash = chain.At(860).GetBlockHash();
    stale_slot.accepted_cursor = Cursor(chain, 860);
    chain.At(860).btcpPrevCommitment = stale_slot.accepted_cursor.btc_hash;
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, config, ACTIVATION_PREDECESSOR_HEIGHT,
        chain.At(880), previous, stale_slot));
}

BOOST_AUTO_TEST_CASE(receipt_state_is_monotonic_and_fixed_cadence)
{
    const auto chainlock_schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock_schedule);
    const BTCCScheduleConfig btcc_schedule{.candidate_origin = 0};
    BOOST_REQUIRE(btcc_schedule.IsValid());
    constexpr int32_t ACTIVATION_PREDECESSOR_HEIGHT{869};

    const uint256 genesis{NonNullHash(21000)};
    const BTCCReceiptState empty;
    BOOST_REQUIRE(empty.IsStructurallyValid());
    BOOST_CHECK((!BTCCReceiptState{
        BTCCursor{}, NonNullHash(21020), 870, 880}.IsStructurallyValid()));

    BTCCReceipt first;
    first.chainlock_target_height = 870;
    first.chainlock_target_hash = NonNullHash(21001);
    first.chainlock_logical_id = NonNullHash(21002);
    first.accepted_cursor = BTCCursor{
        870, NonNullHash(21003), NonNullHash(21004)};
    BOOST_CHECK(BTCCReceiptAdvancesCursor(empty, first));
    BOOST_CHECK(IsExactBTCCReceiptTransition(
        empty, first, BTCCAdvance::ADVANCE));
    BOOST_CHECK(!IsExactBTCCReceiptTransition(
        empty, first, BTCCAdvance::KEEP));

    // H+5 is the signing height. The fixed carrier is H+10 so certificates
    // have a deterministic five-block propagation window.
    BOOST_CHECK(!ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 870,
        NonNullHash(21005), empty, first));
    const auto accepted{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 880,
        NonNullHash(21006), empty, first)};
    BOOST_REQUIRE(accepted);
    BOOST_CHECK(accepted->cursor == first.accepted_cursor);
    BOOST_CHECK(!accepted->cumulative_hash.IsNull());
    BOOST_CHECK_EQUAL(accepted->latest_chainlock_target_height, 870);
    BOOST_CHECK_EQUAL(accepted->latest_receipt_carrier_height, 880);

    BTCCReceipt null_receipt;
    BOOST_CHECK(!BTCCReceiptAdvancesCursor(*accepted, null_receipt));
    const auto kept{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 890,
        NonNullHash(21007), *accepted, null_receipt)};
    BOOST_REQUIRE(kept);
    BOOST_CHECK(*kept == *accepted);

    BTCCReceipt keep_receipt;
    keep_receipt.chainlock_target_height = 880;
    keep_receipt.chainlock_target_hash = NonNullHash(21015);
    keep_receipt.chainlock_logical_id = NonNullHash(21016);
    keep_receipt.accepted_cursor = accepted->cursor;
    BOOST_CHECK(!BTCCReceiptAdvancesCursor(*accepted, keep_receipt));
    BOOST_CHECK(IsExactBTCCReceiptTransition(
        *accepted, keep_receipt, BTCCAdvance::KEEP));
    BOOST_CHECK(!IsExactBTCCReceiptTransition(
        *accepted, keep_receipt, BTCCAdvance::ADVANCE));
    const auto receipted_keep{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 890,
        NonNullHash(21017), *accepted, keep_receipt)};
    BOOST_REQUIRE(receipted_keep);
    BOOST_CHECK(receipted_keep->cursor == accepted->cursor);
    BOOST_CHECK(receipted_keep->cumulative_hash != accepted->cumulative_hash);
    BOOST_CHECK_EQUAL(receipted_keep->latest_chainlock_target_height, 880);
    BOOST_CHECK_EQUAL(receipted_keep->latest_receipt_carrier_height, 890);

    auto wrong_keep{keep_receipt};
    wrong_keep.accepted_cursor.sys_hash = NonNullHash(21018);
    BOOST_CHECK(!ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 890,
        NonNullHash(21019), *accepted, wrong_keep));

    BOOST_CHECK(!ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 900,
        NonNullHash(21009), *accepted, first));

    BTCCReceipt second;
    second.chainlock_target_height = 890;
    second.chainlock_target_hash = NonNullHash(21010);
    second.chainlock_logical_id = NonNullHash(21011);
    second.accepted_cursor = BTCCursor{
        890, NonNullHash(21012), NonNullHash(21013)};
    BOOST_CHECK(BTCCReceiptAdvancesCursor(*receipted_keep, second));
    BOOST_CHECK(IsExactBTCCReceiptTransition(
        *receipted_keep, second, BTCCAdvance::ADVANCE));
    BOOST_CHECK(!IsExactBTCCReceiptTransition(
        *receipted_keep, second, BTCCAdvance::KEEP));
    const auto advanced{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 900,
        NonNullHash(21014), *receipted_keep, second)};
    BOOST_REQUIRE(advanced);
    BOOST_CHECK(advanced->cursor == second.accepted_cursor);
    BOOST_CHECK(advanced->cumulative_hash != accepted->cumulative_hash);
}

BOOST_AUTO_TEST_CASE(initial_receipt_retries_after_null_fixed_carrier)
{
    const auto chainlock_schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock_schedule);
    const BTCCScheduleConfig btcc_schedule{.candidate_origin = 865};
    BOOST_REQUIRE(btcc_schedule.IsValid());
    constexpr int32_t ACTIVATION_PREDECESSOR_HEIGHT{864};
    const auto initial_target{NextEligibleChainLockTargetHeight(
        *chainlock_schedule, ACTIVATION_PREDECESSOR_HEIGHT)};
    BOOST_REQUIRE(initial_target);
    const auto signing_height{
        SigningHeightForTarget(*chainlock_schedule, *initial_target)};
    BOOST_REQUIRE(signing_height);
    const int32_t fixed_carrier{
        *signing_height +
        static_cast<int32_t>(PQ_BTCC_RECEIPT_PROPAGATION_BUFFER)};
    const int32_t retry_carrier{
        fixed_carrier + static_cast<int32_t>(btcc_schedule.candidate_period)};

    const uint256 genesis{NonNullHash(22500)};
    IndexChain chain{896};
    chain.At(*initial_target).btcpPrevCommitment = NonNullHash(22501);

    const BTCCReceiptState empty;
    const BTCCReceipt null_receipt;
    const auto after_null{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, fixed_carrier,
        chain.At(fixed_carrier).GetBlockHash(), empty, null_receipt)};
    BOOST_REQUIRE(after_null);
    BOOST_CHECK(*after_null == empty);

    BTCCReceipt initial;
    initial.chainlock_target_height = *initial_target;
    initial.chainlock_target_hash = chain.At(*initial_target).GetBlockHash();
    initial.chainlock_logical_id = NonNullHash(22502);
    initial.accepted_cursor = Cursor(chain, *initial_target);
    BOOST_REQUIRE(initial.IsStructurallyValid());
    BOOST_CHECK(ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(retry_carrier),
        *after_null, initial));

    const auto receipted{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, retry_carrier,
        chain.At(retry_carrier).GetBlockHash(), *after_null, initial)};
    BOOST_REQUIRE(receipted);
    BOOST_CHECK_EQUAL(receipted->latest_chainlock_target_height,
                      *initial_target);
    BOOST_CHECK_EQUAL(receipted->latest_receipt_carrier_height,
                      retry_carrier);

    const auto reconstructed{ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(retry_carrier),
        *after_null, *receipted, initial.chainlock_logical_id)};
    BOOST_REQUIRE(reconstructed);
    BOOST_CHECK(*reconstructed == initial);

    const int32_t non_initial_target{
        *initial_target + static_cast<int32_t>(btcc_schedule.candidate_period)};
    chain.At(non_initial_target).btcpPrevCommitment = NonNullHash(22503);
    BTCCReceipt non_initial{initial};
    non_initial.chainlock_target_height = non_initial_target;
    non_initial.chainlock_target_hash =
        chain.At(non_initial_target).GetBlockHash();
    non_initial.chainlock_logical_id = NonNullHash(22504);
    non_initial.accepted_cursor = Cursor(chain, non_initial_target);
    BOOST_REQUIRE(non_initial.IsStructurallyValid());
    BOOST_CHECK(!IsBTCCReceiptTargetForCarrier(
        *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, empty, retry_carrier,
        non_initial_target));
    BOOST_CHECK(!ValidateBTCCReceiptOnBranch(
        *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(retry_carrier),
        empty, non_initial));
    BOOST_CHECK(!ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, retry_carrier,
        chain.At(retry_carrier).GetBlockHash(), empty, non_initial));

    BOOST_CHECK(!IsBTCCReceiptTargetForCarrier(
        *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, *receipted,
        retry_carrier + static_cast<int32_t>(btcc_schedule.candidate_period),
        *initial_target));
    BOOST_CHECK(!ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT,
        retry_carrier + static_cast<int32_t>(btcc_schedule.candidate_period),
        chain.At(retry_carrier +
                 static_cast<int32_t>(btcc_schedule.candidate_period))
            .GetBlockHash(),
        *receipted, initial));
}

BOOST_AUTO_TEST_CASE(indexed_receipt_reconstruction_is_exact_and_prune_safe)
{
    const auto chainlock_schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock_schedule);
    const BTCCScheduleConfig btcc_schedule{.candidate_origin = 0};
    BOOST_REQUIRE(btcc_schedule.IsValid());
    constexpr int32_t ACTIVATION_PREDECESSOR_HEIGHT{869};

    const uint256 genesis{NonNullHash(23000)};
    IndexChain chain{891};
    chain.At(870).btcpPrevCommitment = NonNullHash(23001);

    BTCCReceipt receipt;
    receipt.chainlock_target_height = 870;
    receipt.chainlock_target_hash = chain.At(870).GetBlockHash();
    receipt.chainlock_logical_id = NonNullHash(23002);
    receipt.accepted_cursor = Cursor(chain, 870);
    const BTCCReceiptState previous;
    const auto current{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 880,
        chain.At(880).GetBlockHash(), previous, receipt)};
    BOOST_REQUIRE(current);

    const auto reconstructed{ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(880), previous,
        *current, receipt.chainlock_logical_id)};
    BOOST_REQUIRE(reconstructed);
    BOOST_CHECK(*reconstructed == receipt);

    BOOST_CHECK(!ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(880), previous,
        *current, NonNullHash(23003)));
    auto wrong_state{*current};
    wrong_state.cumulative_hash = NonNullHash(23004);
    BOOST_CHECK(!ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(880), previous,
        wrong_state, receipt.chainlock_logical_id));

    const auto null_receipt{ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(890), *current,
        *current, uint256{})};
    BOOST_REQUIRE(null_receipt);
    BOOST_CHECK(null_receipt->IsNull());

    BTCCReceipt keep;
    keep.chainlock_target_height = 880;
    keep.chainlock_target_hash = chain.At(880).GetBlockHash();
    keep.chainlock_logical_id = NonNullHash(23005);
    keep.accepted_cursor = current->cursor;
    const auto kept_state{ApplyBTCCReceiptState(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, 890,
        chain.At(890).GetBlockHash(), *current, keep)};
    BOOST_REQUIRE(kept_state);
    const auto reconstructed_keep{ReconstructBTCCReceipt(
        genesis, *chainlock_schedule, btcc_schedule,
        ACTIVATION_PREDECESSOR_HEIGHT, chain.At(890), *current,
        *kept_state, keep.chainlock_logical_id)};
    BOOST_REQUIRE(reconstructed_keep);
    BOOST_CHECK(*reconstructed_keep == keep);
}

BOOST_AUTO_TEST_SUITE_END()
