// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ios>
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

void SetMembers(QuorumBitmap& bitmap, std::size_t first, std::size_t count)
{
    bitmap.fill(0);
    for (std::size_t member{first}; member < first + count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

CBlock CoinbaseOnlyBlock(const std::vector<unsigned char>& payload)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(
        0, CScript{} << OP_RETURN << payload);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

PaymentAuditScheduleConfig ScheduleConfig(int32_t candidate_origin = 865)
{
    const auto chainlock{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock);
    return PaymentAuditScheduleConfig{
        *chainlock,
        BTCCScheduleConfig{.candidate_origin = candidate_origin},
    };
}

PaymentAuditSeedPoint SeedPoint(int32_t height, uint64_t salt)
{
    return PaymentAuditSeedPoint{
        height,
        NonNullHash(10'000 + salt),
        BTCCursor{height, NonNullHash(20'000 + salt),
                   NonNullHash(30'000 + salt)},
        BTCCAdvance::ADVANCE};
}

PaymentAuditSeed Seed(const PaymentAuditEpochSchedule& schedule)
{
    return PaymentAuditSeed{
        schedule.epoch,
        SeedPoint(schedule.anchor_height, 1),
        800'000,
        800'000 +
            static_cast<int32_t>(PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA),
        NonNullHash(30'002)};
}

AuthenticatedChildSignature Signature(uint16_t salt)
{
    AuthenticatedChildSignature signature;
    signature.key_proof.public_key[0] = 1;
    signature.key_proof.public_key[1] = static_cast<uint8_t>(salt);
    signature.signature[0] = static_cast<uint8_t>(salt);
    signature.signature[1] = static_cast<uint8_t>(salt >> 8);
    return signature;
}

PaymentAuditCommitment ValidCommitment(
    const PaymentAuditScheduleConfig& config,
    const PaymentAuditEpochSchedule& schedule,
    const uint256& genesis_hash)
{
    const uint256 subject_descriptor_hash{NonNullHash(102)};
    const auto round{SelectPaymentAuditRound(
        config, schedule, genesis_hash, subject_descriptor_hash,
        Seed(schedule))};
    BOOST_REQUIRE(round);

    PaymentAuditCommitment commitment;
    commitment.seed = round->seed;
    commitment.selected_row = round->selected_row;
    commitment.response_height = round->response_height;
    commitment.deadline_height = round->deadline_height;
    commitment.response_chainlock_logical_id = NonNullHash(100);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = round->seal_height;
    commitment.subject_epoch = schedule.epoch;
    commitment.subject_quorum_base_hash = NonNullHash(101);
    commitment.subject_descriptor_hash = subject_descriptor_hash;
    SetMembers(commitment.subject_valid_members, 0, QUORUM_SIZE);
    commitment.previous_probation_state_hash = NonNullHash(105);
    return commitment;
}

PaymentAuditStatement ValidStatement(
    const PaymentAuditScheduleConfig& config,
    const PaymentAuditEpochSchedule& schedule,
    const uint256& genesis_hash)
{
    const auto commitment{ValidCommitment(config, schedule, genesis_hash)};
    ChainLockStatement seal;
    seal.height = commitment.seal_height;
    seal.block_hash = NonNullHash(201);
    seal.previous_chainlock_height = commitment.seal_height - 5;
    seal.previous_chainlock_hash = NonNullHash(202);
    seal.quorum_context_hash = NonNullHash(203);
    seal.payment_probation_state_hash =
        commitment.previous_probation_state_hash;
    BOOST_REQUIRE(seal.IsStructurallyValid());
    return PaymentAuditStatement{commitment, seal};
}

FinalPaymentAudit ValidFinalAudit(
    const PaymentAuditScheduleConfig& config,
    const PaymentAuditEpochSchedule& schedule,
    const uint256& genesis_hash,
    uint8_t mask = 0x07)
{
    FinalPaymentAudit audit;
    audit.statement = ValidStatement(config, schedule, genesis_hash);
    audit.selected_quorum_mask = mask;
    audit.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((mask & (uint8_t{1} << slot)) == 0) continue;
        SetMembers(audit.signer_bitmaps[slot], 0, QUORUM_THRESHOLD);
        for (uint16_t member{0}; member < QUORUM_THRESHOLD; ++member) {
            PaymentAuditReportWitness witness;
            SetMembers(witness.observed_members, 0, QUORUM_MIN_VALID);
            witness.authenticated_signature = Signature(
                static_cast<uint16_t>(slot * QUORUM_SIZE + member));
            audit.report_witnesses.push_back(std::move(witness));
        }
    }
    return audit;
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_audit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(schedule_has_24_retrospective_rows_and_retry_window)
{
    const auto config{ScheduleConfig()};
    BOOST_REQUIRE(config.IsValid());
    BOOST_CHECK(!BuildPaymentAuditEpochSchedule(config, 2));

    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    BOOST_REQUIRE(schedule->IsStructurallyValid(config));
    BOOST_CHECK_EQUAL(schedule->rows.size(), PAYMENT_AUDIT_ROW_COUNT);
    BOOST_CHECK_EQUAL(schedule->rows.front().response_height, 865);
    BOOST_CHECK_EQUAL(schedule->rows.back().response_height, 1'095);
    BOOST_CHECK_EQUAL(schedule->rows.back().deadline_height, 1'115);
    BOOST_CHECK_EQUAL(schedule->anchor_height, 1'125);
    BOOST_CHECK_EQUAL(schedule->seal_height, 1'370);
    BOOST_CHECK_EQUAL(schedule->carrier_start_height, 1'385);
    BOOST_CHECK_EQUAL(schedule->carrier_end_height_exclusive, 1'660);
    BOOST_CHECK_EQUAL(PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA, 37U);
    BOOST_CHECK_EQUAL(PAYMENT_AUDIT_SEED_MIN_CONFIRMATIONS, 6U);
    BOOST_CHECK_GE(schedule->seal_height,
                   schedule->anchor_height + PAYMENT_AUDIT_SEAL_DELAY);
    BOOST_CHECK(!IsBTCCCandidateHeight(config.btcc,
                                      schedule->seal_height));

    for (std::size_t row{0}; row < schedule->rows.size(); ++row) {
        BOOST_CHECK_EQUAL(
            schedule->rows[row].response_height,
            schedule->rows.front().response_height +
                static_cast<int32_t>(row * PAYMENT_AUDIT_ROW_PERIOD));
        BOOST_CHECK_EQUAL(
            schedule->rows[row].deadline_height,
            schedule->rows[row].response_height +
                PAYMENT_AUDIT_ROW_DEADLINE_DELAY);
        BOOST_CHECK_LT(schedule->rows[row].deadline_height,
                       schedule->anchor_height);
    }

    std::size_t carriers{0};
    for (int32_t height{schedule->carrier_start_height};
         height < schedule->carrier_end_height_exclusive; ++height) {
        const auto owner{PaymentAuditReceiptSlotEpoch(config, height)};
        if (!owner) continue;
        BOOST_CHECK_EQUAL(*owner, schedule->epoch);
        BOOST_CHECK(IsBTCCReceiptCarrierHeight(config.btcc, height));
        ++carriers;
    }
    BOOST_CHECK_EQUAL(carriers, 28U);
    BOOST_CHECK(!PaymentAuditReceiptSlotEpoch(
        config, schedule->carrier_start_height - 10));
    BOOST_CHECK(!PaymentAuditReceiptSlotEpoch(
        config, schedule->carrier_end_height_exclusive + 5));

    const auto next{BuildPaymentAuditEpochSchedule(config, 4)};
    BOOST_REQUIRE(next);
    BOOST_CHECK_LE(schedule->carrier_end_height_exclusive,
                   next->carrier_start_height);
}

BOOST_AUTO_TEST_CASE(audit_windows_end_before_the_next_sealed_state)
{
    const auto config{ScheduleConfig()};
    bool saw_27_carriers{false};
    bool saw_28_carriers{false};
    for (uint32_t epoch{3}; epoch < 18; ++epoch) {
        const auto schedule{BuildPaymentAuditEpochSchedule(config, epoch)};
        const auto next{BuildPaymentAuditEpochSchedule(config, epoch + 1)};
        BOOST_REQUIRE(schedule);
        BOOST_REQUIRE(next);
        BOOST_CHECK_EQUAL(schedule->rows.size(),
                          PAYMENT_AUDIT_ROW_COUNT);
        BOOST_CHECK_EQUAL(schedule->carrier_end_height_exclusive,
                          next->seal_height);
        BOOST_CHECK_LT(schedule->carrier_end_height_exclusive,
                       next->carrier_start_height);
        BOOST_CHECK(IsBTCCCandidateHeight(config.btcc,
                                         schedule->anchor_height));
        BOOST_CHECK(!IsBTCCCandidateHeight(config.btcc,
                                          schedule->seal_height));

        std::size_t carriers{0};
        for (int32_t height{schedule->carrier_start_height};
             height < schedule->carrier_end_height_exclusive;
             height += static_cast<int32_t>(PQ_BTCC_CANDIDATE_PERIOD)) {
            const auto owner{
                PaymentAuditReceiptSlotEpoch(config, height)};
            BOOST_REQUIRE(owner);
            BOOST_CHECK_EQUAL(*owner, epoch);
            ++carriers;
        }
        BOOST_CHECK(carriers == 27U || carriers == 28U);
        saw_27_carriers |= carriers == 27U;
        saw_28_carriers |= carriers == 28U;
    }
    BOOST_CHECK(saw_27_carriers);
    BOOST_CHECK(saw_28_carriers);
}

BOOST_AUTO_TEST_CASE(schedule_alignment_and_overflow_fail_closed)
{
    auto misaligned{ScheduleConfig(866)};
    BOOST_CHECK(!misaligned.IsValid());
    BOOST_CHECK(!BuildPaymentAuditEpochSchedule(misaligned, 3));
    BOOST_CHECK(!BuildPaymentAuditEpochSchedule(
        ScheduleConfig(), std::numeric_limits<uint32_t>::max()));

    auto changed{*BuildPaymentAuditEpochSchedule(ScheduleConfig(), 3)};
    ++changed.rows[17].deadline_height;
    BOOST_CHECK(!changed.IsStructurallyValid(ScheduleConfig()));
    changed = *BuildPaymentAuditEpochSchedule(ScheduleConfig(), 3);
    changed.carrier_end_height_exclusive =
        changed.carrier_start_height - 1;
    BOOST_CHECK(!changed.IsStructurallyValid(ScheduleConfig()));
}

BOOST_AUTO_TEST_CASE(delayed_bitcoin_seed_selects_one_frozen_row)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(10)};
    const uint256 descriptor_hash{NonNullHash(11)};
    const auto seed{Seed(*schedule)};
    BOOST_REQUIRE(seed.IsStructurallyValid());

    const auto round{SelectPaymentAuditRound(
        config, *schedule, genesis_hash, descriptor_hash, seed)};
    BOOST_REQUIRE(round);
    BOOST_CHECK_LT(round->selected_row, PAYMENT_AUDIT_ROW_COUNT);
    BOOST_CHECK_EQUAL(round->response_height,
                      schedule->rows[round->selected_row].response_height);
    BOOST_CHECK_EQUAL(round->deadline_height,
                      schedule->rows[round->selected_row].deadline_height);
    BOOST_CHECK_LT(round->deadline_height, seed.anchor.target_height);

    const uint256 selection{GetPaymentAuditSelectionHash(
        genesis_hash, descriptor_hash, seed)};
    BOOST_CHECK(selection != GetPaymentAuditSelectionHash(
                                 genesis_hash, NonNullHash(12), seed));
    auto changed_anchor{seed};
    changed_anchor.anchor.chainlock_logical_id = NonNullHash(13);
    BOOST_CHECK(selection != GetPaymentAuditSelectionHash(
                                 genesis_hash, descriptor_hash,
                                 changed_anchor));
    auto changed_future{seed};
    changed_future.future_btc_hash = NonNullHash(14);
    BOOST_CHECK(selection != GetPaymentAuditSelectionHash(
                                 genesis_hash, descriptor_hash,
                                 changed_future));

    auto keep{seed};
    keep.anchor.advance = BTCCAdvance::KEEP;
    BOOST_CHECK(!keep.IsStructurallyValid());
    BOOST_CHECK(!SelectPaymentAuditRound(
        config, *schedule, genesis_hash, descriptor_hash, keep));
    auto repeated_btc{seed};
    repeated_btc.future_btc_hash =
        repeated_btc.anchor.accepted_cursor.btc_hash;
    BOOST_CHECK(!repeated_btc.IsStructurallyValid());
    auto wrong_height{seed};
    ++wrong_height.future_btc_height;
    BOOST_CHECK(!SelectPaymentAuditRound(
        config, *schedule, genesis_hash, descriptor_hash, wrong_height));
}

BOOST_AUTO_TEST_CASE(commitment_is_carrier_independent_and_canonical)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(20)};
    auto commitment{ValidCommitment(config, *schedule, genesis_hash)};
    BOOST_REQUIRE(commitment.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(commitment) == commitment);

    auto too_few_subjects{commitment};
    SetMembers(too_few_subjects.subject_valid_members, 0,
               QUORUM_MIN_VALID);
    too_few_subjects.subject_valid_members[0] &=
        static_cast<uint8_t>(~uint8_t{1});
    BOOST_CHECK(!too_few_subjects.IsStructurallyValid());
    auto keep{commitment};
    keep.response_advance = BTCCAdvance::KEEP;
    BOOST_CHECK(!keep.IsStructurallyValid());
    auto legacy{commitment};
    legacy.version = PAYMENT_AUDIT_V1_VERSION;
    BOOST_CHECK(!legacy.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(reporter_thresholds_derive_semantic_result_hash)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(25)};
    auto audit{ValidFinalAudit(config, *schedule, genesis_hash)};
    const auto classification{ClassifyPaymentAuditReports(audit)};
    BOOST_REQUIRE(classification);
    BOOST_CHECK_EQUAL(classification->online_count, QUORUM_MIN_VALID);
    BOOST_CHECK(classification->conclusive);
    BOOST_CHECK_EQUAL(CountSet(classification->missed_members),
                      QUORUM_SIZE - QUORUM_MIN_VALID);

    const uint256 result_hash{GetPaymentAuditResultHash(
        genesis_hash, audit, *classification)};
    auto signature_variant{audit};
    signature_variant.report_witnesses[0]
        .authenticated_signature.signature[7] ^= 1;
    const auto same_classification{
        ClassifyPaymentAuditReports(signature_variant)};
    BOOST_REQUIRE(same_classification);
    BOOST_CHECK_EQUAL(GetPaymentAuditResultHash(
                          genesis_hash, signature_variant,
                          *same_classification),
                      result_hash);
    BOOST_CHECK(signature_variant.GetWitnessId(genesis_hash) !=
                audit.GetWitnessId(genesis_hash));

    for (auto& witness : audit.report_witnesses) {
        witness.observed_members.fill(0);
    }
    std::size_t offset{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((audit.selected_quorum_mask & (uint8_t{1} << slot)) == 0) {
            continue;
        }
        for (std::size_t reporter{0}; reporter < QUORUM_THRESHOLD;
             ++reporter, ++offset) {
            if (reporter < 134) {
                audit.report_witnesses[offset].observed_members[0] |= 0x01;
            }
            if (reporter < 133) {
                audit.report_witnesses[offset].observed_members[0] |= 0x02;
            }
        }
    }
    const auto border{ClassifyPaymentAuditReports(audit)};
    BOOST_REQUIRE(border);
    BOOST_CHECK((border->online_members[0] & 0x01) != 0);
    BOOST_CHECK((border->online_members[0] & 0x02) == 0);
    BOOST_CHECK((border->missed_members[0] & 0x02) != 0);
    BOOST_CHECK(!border->conclusive);
    BOOST_CHECK(GetPaymentAuditResultHash(genesis_hash, audit, *border) !=
                result_hash);
}

BOOST_AUTO_TEST_CASE(two_broad_reporter_rosters_survive_any_three_of_four_mask)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(26)};

    for (const uint8_t mask : {uint8_t{0x07}, uint8_t{0x0b},
                               uint8_t{0x0d}, uint8_t{0x0e}}) {
        auto audit{ValidFinalAudit(config, *schedule, genesis_hash, mask)};
        std::size_t offset{0};
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            if ((mask & (uint8_t{1} << slot)) == 0) continue;
            for (std::size_t reporter{0}; reporter < QUORUM_THRESHOLD;
                 ++reporter, ++offset) {
                auto& observed{
                    audit.report_witnesses[offset].observed_members};
                observed.fill(0);
                if (slot < 2) observed[0] |= 0x01;
            }
        }
        BOOST_REQUIRE_EQUAL(offset, audit.report_witnesses.size());
        const auto classification{ClassifyPaymentAuditReports(audit)};
        BOOST_REQUIRE(classification);
        BOOST_CHECK((classification->online_members[0] & 0x01) != 0);
        BOOST_CHECK((classification->missed_members[0] & 0x02) != 0);
    }

    // One broadly reached roster can still be the omitted fourth roster.
    auto one_roster{ValidFinalAudit(
        config, *schedule, genesis_hash, /*mask=*/0x0e)};
    for (auto& witness : one_roster.report_witnesses) {
        witness.observed_members.fill(0);
    }
    const auto omitted{ClassifyPaymentAuditReports(one_roster)};
    BOOST_REQUIRE(omitted);
    BOOST_CHECK((omitted->online_members[0] & 0x01) == 0);
    BOOST_CHECK((omitted->missed_members[0] & 0x01) != 0);
}

BOOST_AUTO_TEST_CASE(share_and_final_certificate_keep_three_of_four_geometry)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(30)};

    PaymentAuditShare share;
    share.transcript.statement = ValidStatement(
        config, *schedule, genesis_hash);
    SetMembers(share.transcript.reporter_observed_members, 0,
               QUORUM_MIN_VALID);
    share.transcript.quorum_epoch = 1;
    share.transcript.quorum_base_hash = NonNullHash(31);
    share.transcript.member_index = 17;
    share.transcript.member_pro_tx_hash = NonNullHash(32);
    share.authenticated_signature = Signature(17);
    BOOST_REQUIRE(share.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(share) == share);
    BOOST_CHECK(!share.GetId(genesis_hash).IsNull());

    auto audit{ValidFinalAudit(config, *schedule, genesis_hash)};
    BOOST_REQUIRE(audit.IsStructurallyValid());
    DataStream encoded;
    encoded << audit;
    BOOST_CHECK_EQUAL(encoded.size(), FinalPaymentAudit::WIRE_SIZE);
    FinalPaymentAudit decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK(decoded == audit);

    auto alternate{ValidFinalAudit(
        config, *schedule, genesis_hash, 0x0e)};
    alternate.report_witnesses.back()
        .authenticated_signature.signature[7] ^= 1;
    BOOST_REQUIRE(alternate.IsStructurallyValid());
    BOOST_CHECK(alternate.GetLogicalId(genesis_hash) ==
                audit.GetLogicalId(genesis_hash));
    BOOST_CHECK(alternate.GetWitnessId(genesis_hash) !=
                audit.GetWitnessId(genesis_hash));

    auto two_rosters{audit};
    two_rosters.selected_quorum_mask = 0x03;
    two_rosters.signer_bitmaps[2].fill(0);
    two_rosters.report_witnesses.resize(2 * QUORUM_THRESHOLD);
    BOOST_CHECK(!two_rosters.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(same_epoch_incompatible_candidate_does_not_suppress_rebuild)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(35)};
    const auto active{ValidFinalAudit(config, *schedule, genesis_hash)};
    BOOST_REQUIRE(IsPaymentAuditCandidateCompatible(
        active, active.statement));

    auto stale_root{active};
    stale_root.statement.commitment.previous_probation_state_hash =
        NonNullHash(36);
    stale_root.statement.seal_statement.payment_probation_state_hash =
        stale_root.statement.commitment.previous_probation_state_hash;
    BOOST_REQUIRE(stale_root.IsStructurallyValid());
    BOOST_CHECK_EQUAL(
        stale_root.statement.commitment.seed.epoch,
        active.statement.commitment.seed.epoch);
    BOOST_CHECK(!IsPaymentAuditCandidateCompatible(
        stale_root, active.statement));

    auto stale_seal{active};
    stale_seal.statement.seal_statement.block_hash = NonNullHash(37);
    BOOST_REQUIRE(stale_seal.IsStructurallyValid());
    BOOST_CHECK(!IsPaymentAuditCandidateCompatible(
        stale_seal, active.statement));
}

BOOST_AUTO_TEST_CASE(parser_rejects_signature_count_before_allocation)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const auto audit{ValidFinalAudit(
        config, *schedule, NonNullHash(40))};
    DataStream encoded;
    encoded << audit;
    constexpr std::size_t count_offset{
        PaymentAuditStatement::WIRE_SIZE + sizeof(uint8_t) +
        ACTIVE_QUORUMS * BITMAP_SIZE};
    encoded[count_offset] = static_cast<std::byte>(0);
    encoded[count_offset + 1] = static_cast<std::byte>(0);
    FinalPaymentAudit decoded;
    BOOST_CHECK_THROW(encoded >> decoded, std::ios_base::failure);
    BOOST_CHECK(decoded.report_witnesses.empty());
}

BOOST_AUTO_TEST_CASE(null_then_later_nonnull_carrier_applies_once)
{
    const auto config{ScheduleConfig()};
    const auto schedule{BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);
    const uint256 genesis_hash{NonNullHash(50)};
    PaymentAuditReceiptState state;
    BOOST_REQUIRE(state.IsStructurallyValid());
    PaymentAuditReceipt null_receipt;
    BOOST_CHECK(null_receipt.IsNull());
    const auto unchanged{ApplyPaymentAuditReceipt(
        genesis_hash, state, null_receipt)};
    BOOST_REQUIRE(unchanged);
    BOOST_CHECK(*unchanged == state);

    PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = schedule->epoch;
    receipt.seal_height = schedule->seal_height;
    receipt.seal_block_hash = NonNullHash(51);
    receipt.carrier_height = schedule->carrier_start_height + 20;
    receipt.audit_logical_id = NonNullHash(52);
    receipt.audit_witness_id = NonNullHash(53);
    receipt.commitment_hash = NonNullHash(54);
    receipt.result_hash = NonNullHash(55);
    receipt.next_probation_state_hash = NonNullHash(56);
    SetMembers(receipt.online_members, 7, 3);
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    BOOST_CHECK_EQUAL(*PaymentAuditReceiptSlotEpoch(
                          config, receipt.carrier_height),
                      receipt.epoch);
    const auto next{ApplyPaymentAuditReceipt(
        genesis_hash, state, receipt)};
    BOOST_REQUIRE(next);
    BOOST_CHECK_EQUAL(next->cursor.epoch, schedule->epoch);
    BOOST_CHECK(!ApplyPaymentAuditReceipt(
        genesis_hash, *next, receipt));

    auto premature{receipt};
    premature.carrier_height = receipt.seal_height + 5;
    BOOST_CHECK(!premature.IsStructurallyValid());
    auto expired{receipt};
    expired.carrier_height = schedule->carrier_end_height_exclusive + 5;
    BOOST_REQUIRE(expired.IsStructurallyValid());
    BOOST_CHECK(!PaymentAuditReceiptSlotEpoch(
        config, expired.carrier_height));
}

BOOST_AUTO_TEST_CASE(payment_audit_receipt_v3_commits_online_members)
{
    PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = 4;
    receipt.seal_height = 1'000;
    receipt.seal_block_hash = NonNullHash(60);
    receipt.carrier_height = 1'010;
    receipt.audit_logical_id = NonNullHash(61);
    receipt.audit_witness_id = NonNullHash(62);
    receipt.commitment_hash = NonNullHash(63);
    receipt.result_hash = NonNullHash(64);
    receipt.next_probation_state_hash = NonNullHash(65);
    SetMembers(receipt.online_members, 17, 11);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    DataStream encoded;
    encoded << receipt;
    BOOST_CHECK_EQUAL(encoded.size(), PaymentAuditReceipt::WIRE_SIZE);
    const auto bytes{MakeUCharSpan(encoded)};
    BOOST_REQUIRE(bytes.size() >= receipt.online_members.size());
    BOOST_CHECK(std::equal(
        receipt.online_members.begin(), receipt.online_members.end(),
        bytes.end() - receipt.online_members.size()));

    PaymentAuditReceipt decoded;
    encoded >> decoded;
    BOOST_CHECK(decoded == receipt);

    PaymentAuditReceipt noncanonical_null;
    noncanonical_null.online_members[0] = 1;
    BOOST_CHECK(!noncanonical_null.IsNull());
    BOOST_CHECK(!noncanonical_null.IsStructurallyValid());

    auto legacy{receipt};
    legacy.version = 2;
    BOOST_CHECK(!legacy.IsStructurallyValid());
    DataStream legacy_wire;
    legacy_wire << legacy;
    PaymentAuditReceipt rejected;
    BOOST_CHECK_THROW(legacy_wire >> rejected, std::ios_base::failure);

    DataStream actual_v2_wire;
    const uint16_t legacy_version{2};
    actual_v2_wire << legacy_version << receipt.has_audit << receipt.epoch
                   << receipt.seal_height << receipt.seal_block_hash
                   << receipt.carrier_height << receipt.audit_logical_id
                   << receipt.audit_witness_id << receipt.commitment_hash
                   << receipt.result_hash
                   << receipt.next_probation_state_hash;
    BOOST_CHECK_EQUAL(actual_v2_wire.size(), 207U);
    BOOST_CHECK_THROW(actual_v2_wire >> rejected,
                      std::ios_base::failure);

    const uint256 genesis_hash{NonNullHash(66)};
    PaymentAuditReceiptState state;
    const auto first{ApplyPaymentAuditReceipt(genesis_hash, state, receipt)};
    BOOST_REQUIRE(first);
    auto alternate{receipt};
    alternate.online_members[0] ^= 1;
    const auto second{
        ApplyPaymentAuditReceipt(genesis_hash, state, alternate)};
    BOOST_REQUIRE(second);
    BOOST_CHECK(first->cursor == second->cursor);
    BOOST_CHECK(first->cumulative_hash != second->cumulative_hash);
}

BOOST_AUTO_TEST_CASE(audit_tail_precedes_btcc_and_allows_opaque_magic)
{
    PaymentAuditReceipt expected;
    expected.has_audit = 1;
    expected.epoch = 4;
    expected.seal_height = 1'000;
    expected.seal_block_hash = NonNullHash(70);
    expected.carrier_height = 1'010;
    expected.audit_logical_id = NonNullHash(71);
    expected.audit_witness_id = NonNullHash(72);
    expected.commitment_hash = NonNullHash(73);
    std::copy(std::begin(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
              std::end(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES),
              expected.commitment_hash.begin());
    expected.result_hash = NonNullHash(74);
    expected.next_probation_state_hash = NonNullHash(75);
    SetMembers(expected.online_members, 31, 5);
    BOOST_REQUIRE(expected.IsStructurallyValid());

    const BTCCReceipt btcc;
    DataStream tail;
    tail << PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES << expected
         << BTCC_RECEIPT_MAGIC_BYTES << btcc;
    const auto bytes{MakeUCharSpan(tail)};
    std::vector<unsigned char> payload{bytes.begin(), bytes.end()};

    auto block{CoinbaseOnlyBlock(payload)};
    PaymentAuditReceipt decoded;
    BOOST_CHECK(HasPaymentAuditReceiptCommitment(block));
    BOOST_CHECK(ExtractPaymentAuditReceipt(block, decoded));
    BOOST_CHECK(decoded == expected);

    DataStream btcprev;
    btcprev << BTCPREV_MAGIC_BYTES << NonNullHash(76);
    const auto btcprev_bytes{MakeUCharSpan(btcprev)};
    payload.insert(payload.end(), btcprev_bytes.begin(),
                   btcprev_bytes.end());
    block = CoinbaseOnlyBlock(payload);
    BOOST_CHECK(HasPaymentAuditReceiptCommitment(block));
    BOOST_CHECK(ExtractPaymentAuditReceipt(block, decoded));
    BOOST_CHECK(decoded == expected);

    payload.pop_back();
    block = CoinbaseOnlyBlock(payload);
    BOOST_CHECK(HasPaymentAuditReceiptCommitment(block));
    BOOST_CHECK(!ExtractPaymentAuditReceipt(block, decoded));

    constexpr std::size_t audit_segment_size{
        sizeof(PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES) +
        PaymentAuditReceipt::WIRE_SIZE};
    std::vector<unsigned char> pqar_only{bytes.begin(), bytes.end()};
    pqar_only[audit_segment_size] ^= 1;
    block = CoinbaseOnlyBlock(pqar_only);
    BOOST_CHECK(!HasPaymentAuditReceiptCommitment(block));

    std::vector<unsigned char> misaligned_btcr{bytes.begin(), bytes.end()};
    misaligned_btcr.insert(
        misaligned_btcr.begin() + audit_segment_size, 0);
    block = CoinbaseOnlyBlock(misaligned_btcr);
    BOOST_CHECK(!HasPaymentAuditReceiptCommitment(block));
}

BOOST_AUTO_TEST_SUITE_END()
