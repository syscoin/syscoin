// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_signer.h>
#include <llmq/pq_payment_audit_store.h>

#include <crypto/scheduled_wots/scheduled_wots.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

constexpr uint8_t AUTHORIZATION_MASK{0b0111};
constexpr uint32_t SUBJECT_EPOCH{6};
constexpr std::size_t SUBJECT_QUORUM_SLOT{ACTIVE_QUORUMS - 2};

uint256 NonNullHash(uint64_t value)
{
    uint256 hash;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        hash.begin()[byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    bitmap.fill(0);
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

ChildPublicKey UniqueChildKey(std::size_t slot, std::size_t member)
{
    ChildPublicKey key{};
    const uint64_t value{1 + slot * QUORUM_SIZE + member};
    key[0] = 0xc1;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        key[1 + byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    return key;
}

struct AuditVerificationFixture {
    uint256 genesis_hash{NonNullHash(1)};
    PaymentAuditScheduleConfig schedule{
        ChainLockScheduleConfig{.epoch_origin = 0},
        BTCCScheduleConfig{.candidate_origin = 865}};
    FinalChainLock seal;
    FinalPaymentAudit audit;
    FrozenQuorumRosters rosters;
};

std::unique_ptr<AuditVerificationFixture> MakeFixture()
{
    auto fixture{std::make_unique<AuditVerificationFixture>()};
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(fixture->schedule, SUBJECT_EPOCH)};
    BOOST_REQUIRE(audit_schedule);
    fixture->seal.statement.height = audit_schedule->seal_height;
    fixture->seal.statement.block_hash = NonNullHash(2);
    fixture->seal.statement.previous_chainlock_height =
        fixture->seal.statement.height - PQ_CL_PERIOD;
    fixture->seal.statement.previous_chainlock_hash = NonNullHash(3);
    fixture->seal.statement.quorum_context_hash = NonNullHash(4);
    fixture->seal.statement.payment_probation_state_hash = NonNullHash(5);
    fixture->seal.selected_quorum_mask = 0x07;
    fixture->seal.signatures.resize(FINAL_SIGNATURE_COUNT);

    const auto active_epochs{ActiveEpochsAtHeight(
        fixture->schedule.chainlock, fixture->seal.statement.height)};
    BOOST_REQUIRE(active_epochs);

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = (*active_epochs)[slot].epoch;
        descriptor.base_height = (*active_epochs)[slot].base_height;
        descriptor.base_hash = NonNullHash(10 + slot);
        descriptor.snapshot_height = descriptor.base_height - 100;
        descriptor.snapshot_hash = NonNullHash(20 + slot);
        SetFirstMembers(descriptor.valid_members, QUORUM_MIN_VALID);
        descriptor.valid_count = QUORUM_MIN_VALID;
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            auto& frozen{roster.members[member]};
            frozen.pro_tx_hash =
                NonNullHash(100 + slot * 1'000 + member);
            frozen.eligible = member < QUORUM_MIN_VALID;
            if (!frozen.eligible) continue;
            frozen.child_root = test::MakeSyntheticChildAuthorization(
                                    fixture->genesis_hash,
                                    frozen.pro_tx_hash,
                                    descriptor.epoch,
                                    UniqueChildKey(slot, member),
                                    1 + slot * QUORUM_SIZE + member)
                                    .record;
        }
        descriptor.member_root =
            ComputeQuorumMemberRoot(fixture->genesis_hash, roster);
        descriptor.child_key_root =
            ComputeQuorumChildKeyRoot(fixture->genesis_hash, roster);
        if (slot < REQUIRED_QUORUMS) {
            SetFirstMembers(fixture->seal.signer_bitmaps[slot],
                            QUORUM_THRESHOLD);
        }
    }
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    fixture->seal.statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, fixture->seal.statement.height,
        fixture->seal.statement.block_hash, descriptors);
    for (auto& signature : fixture->seal.signatures) {
        signature.key_proof.public_key[0] = 1;
    }

    PaymentAuditCommitment commitment;
    commitment.seed.epoch = SUBJECT_EPOCH;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        audit_schedule->anchor_height, NonNullHash(30),
        BTCCursor{audit_schedule->anchor_height, NonNullHash(31),
                  NonNullHash(32)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(33);
    commitment.selected_row = 2;
    commitment.response_height = audit_schedule->rows[2].response_height;
    commitment.deadline_height = audit_schedule->rows[2].deadline_height;
    commitment.response_chainlock_logical_id = NonNullHash(33);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = fixture->seal.statement.height;
    commitment.subject_epoch = SUBJECT_EPOCH;
    commitment.subject_quorum_base_hash =
        fixture->rosters[SUBJECT_QUORUM_SLOT].descriptor.base_hash;
    commitment.subject_descriptor_hash = NonNullHash(34);
    SetFirstMembers(commitment.subject_valid_members, QUORUM_MIN_VALID);
    commitment.previous_probation_state_hash =
        fixture->seal.statement.payment_probation_state_hash;
    fixture->audit.statement = PaymentAuditStatement{
        commitment, fixture->seal.statement};
    fixture->audit.selected_quorum_mask = 0x07;
    fixture->audit.report_witnesses.reserve(
        PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        SetFirstMembers(fixture->audit.signer_bitmaps[slot],
                        QUORUM_THRESHOLD);
        for (std::size_t member{0}; member < QUORUM_THRESHOLD; ++member) {
            const auto authorization{test::MakeSyntheticChildAuthorization(
                fixture->genesis_hash,
                fixture->rosters[slot].members[member].pro_tx_hash,
                fixture->rosters[slot].descriptor.epoch,
                UniqueChildKey(slot, member),
                1 + slot * QUORUM_SIZE + member)};
            PaymentAuditReportWitness witness;
            SetFirstMembers(witness.observed_members, QUORUM_MIN_VALID);
            witness.authenticated_signature.key_proof =
                authorization.proof;
            witness.authenticated_signature.signature[0] =
                static_cast<uint8_t>(member);
            fixture->audit.report_witnesses.push_back(
                std::move(witness));
        }
    }
    BOOST_REQUIRE(fixture->seal.IsStructurallyValid());
    BOOST_REQUIRE(fixture->audit.IsStructurallyValid());
    return fixture;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_payment_audit_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fresh_archive_preflight_needs_no_old_chainlock_store)
{
    // The embedded B statement and 801 audit witnesses are the durable
    // historical proof. This fixture deliberately has no ChainLock store.
    const auto fixture{MakeFixture()};
    PaymentAuditVerificationError error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    const auto prepared{PrepareFinalPaymentAuditVerification(
        fixture->genesis_hash, fixture->schedule, fixture->audit,
        fixture->rosters,
        AUTHORIZATION_MASK, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(error == PaymentAuditVerificationError::NONE);
    BOOST_CHECK_EQUAL(prepared->checks.size(),
                      PAYMENT_AUDIT_SIGNATURE_COUNT);

    const auto transcript{BuildPaymentAuditShareTranscript(
        fixture->audit.statement,
        fixture->audit.report_witnesses[QUORUM_THRESHOLD]
            .observed_members,
        fixture->rosters[1].descriptor, 0,
        fixture->rosters[1].members[0].pro_tx_hash)};
    const uint256 expected{
        GetPaymentAuditShareHash(fixture->genesis_hash, transcript)};
    BOOST_CHECK_EQUAL_COLLECTIONS(
        prepared->checks[QUORUM_THRESHOLD].GetMessageBytes().begin(),
        prepared->checks[QUORUM_THRESHOLD].GetMessageBytes().end(),
        expected.begin(), expected.end());
    const auto expected_leaf{PaymentAuditLeafIndex(
        fixture->schedule, SUBJECT_EPOCH,
        fixture->audit.statement.commitment.seal_height,
        fixture->rosters[1].descriptor.epoch)};
    BOOST_REQUIRE(expected_leaf);
    BOOST_CHECK_EQUAL(
        prepared->checks[QUORUM_THRESHOLD].GetLeafIndex(), *expected_leaf);
}

BOOST_AUTO_TEST_CASE(preparation_rejects_wrong_seal_context_and_membership)
{
    PaymentAuditVerificationError error{PaymentAuditVerificationError::NONE};
    auto wrong_seal{MakeFixture()};
    wrong_seal->seal.statement.block_hash = NonNullHash(500);
    BOOST_CHECK(!ValidatePaymentAuditLiveSeal(
        wrong_seal->genesis_hash, wrong_seal->audit.statement,
        wrong_seal->seal, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_SEAL);

    auto wrong_seal_and_context{MakeFixture()};
    wrong_seal_and_context->seal.statement.block_hash = NonNullHash(501);
    wrong_seal_and_context->rosters[0].descriptor.member_root.begin()[0] ^= 1;
    BOOST_CHECK(!PreparedPaymentAuditContext::Create(
        wrong_seal_and_context->genesis_hash,
        wrong_seal_and_context->schedule,
        wrong_seal_and_context->audit.statement,
        wrong_seal_and_context->seal,
        std::make_shared<const FrozenQuorumRosters>(
            wrong_seal_and_context->rosters),
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_SEAL);

    auto wrong_context{MakeFixture()};
    wrong_context->rosters[0].descriptor.member_root.begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        wrong_context->genesis_hash, wrong_context->schedule,
        wrong_context->audit,
        wrong_context->rosters, AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);
    BOOST_CHECK(!PreparedPaymentAuditContext::Create(
        wrong_context->genesis_hash, wrong_context->schedule,
        wrong_context->audit.statement, wrong_context->seal,
        std::make_shared<const FrozenQuorumRosters>(wrong_context->rosters),
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);

    auto wrong_proof{MakeFixture()};
    wrong_proof->audit.report_witnesses[0]
        .authenticated_signature.key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        wrong_proof->genesis_hash, wrong_proof->schedule,
        wrong_proof->audit,
        wrong_proof->rosters, AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CHILD_PROOF);
}

BOOST_AUTO_TEST_CASE(full_verifier_reports_invalid_signature_after_preflight)
{
    const auto fixture{MakeFixture()};
    PaymentAuditVerificationError error{PaymentAuditVerificationError::NONE};
    BOOST_CHECK(!VerifyFinalPaymentAudit(
        fixture->genesis_hash, fixture->schedule, fixture->audit,
        fixture->rosters,
        AUTHORIZATION_MASK, nullptr, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_SIGNATURE);
}

BOOST_AUTO_TEST_CASE(preserved_archive_is_reverified_after_restart_and_reindex)
{
    const auto fixture{MakeFixture()};
    const fs::path archive_path{
        m_path_root / "pq_payment_audit_verify_restart"};
    const fs::path reindex_path{
        m_path_root / "pq_payment_audit_verify_reindex"};
    const uint256 witness_id{
        fixture->audit.GetWitnessId(fixture->genesis_hash)};

    // AcceptVerified is the archive's caller-side trust boundary. Persisting
    // a structurally valid certificate must never substitute for checking
    // its 801 signatures when a receipt is replayed.
    {
        PaymentAuditStore archive{archive_path, fixture->genesis_hash};
        BOOST_REQUIRE(archive.IsHealthy());
        BOOST_REQUIRE(archive.AcceptVerified(fixture->audit) ==
                      PaymentAuditStoreResult::ACCEPTED);
    }

    FinalPaymentAudit preserved;
    {
        PaymentAuditStore restarted{archive_path, fixture->genesis_hash};
        BOOST_REQUIRE(restarted.IsHealthy());
        const auto loaded{restarted.Get(witness_id)};
        BOOST_REQUIRE(loaded);
        preserved = *loaded;

        PaymentAuditVerificationError error{
            PaymentAuditVerificationError::NONE};
        BOOST_CHECK(!VerifyFinalPaymentAudit(
            fixture->genesis_hash, fixture->schedule, preserved,
            fixture->rosters,
            AUTHORIZATION_MASK, nullptr, &error));
        BOOST_CHECK(error ==
                    PaymentAuditVerificationError::INVALID_SIGNATURE);
    }

    // A fresh index/archive import has the same rule: the exact stored bytes
    // are only an availability cache, never a persisted verification marker.
    {
        PaymentAuditStore reindexed{reindex_path, fixture->genesis_hash};
        BOOST_REQUIRE(reindexed.IsHealthy());
        BOOST_REQUIRE(reindexed.AcceptVerified(preserved) ==
                      PaymentAuditStoreResult::ACCEPTED);
        const auto loaded{reindexed.Get(witness_id)};
        BOOST_REQUIRE(loaded);

        PaymentAuditVerificationError error{
            PaymentAuditVerificationError::NONE};
        BOOST_CHECK(!VerifyFinalPaymentAudit(
            fixture->genesis_hash, fixture->schedule, *loaded,
            fixture->rosters,
            AUTHORIZATION_MASK, nullptr, &error));
        BOOST_CHECK(error ==
                    PaymentAuditVerificationError::INVALID_SIGNATURE);
    }
}

BOOST_AUTO_TEST_CASE(real_scheduled_wots_share_verifies_and_enters_collector)
{
    auto fixture{MakeFixture()};
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i + 1);
    }
    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));

    const auto& member{fixture->rosters[0].members[0]};
    auto authorization{test::MakeSyntheticChildAuthorization(
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->rosters[0].descriptor.epoch,
        public_key, 90'001)};
    fixture->rosters[0].members[0].child_root = authorization.record;
    fixture->rosters[0].descriptor.child_key_root =
        ComputeQuorumChildKeyRoot(fixture->genesis_hash,
                                  fixture->rosters[0]);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    fixture->seal.statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, fixture->seal.statement.height,
        fixture->seal.statement.block_hash, descriptors);
    fixture->audit.statement.seal_statement = fixture->seal.statement;
    BOOST_REQUIRE(fixture->audit.statement.IsStructurallyValid());
    BOOST_REQUIRE(fixture->seal.IsStructurallyValid());

    PaymentAuditShare share;
    share.transcript = BuildPaymentAuditShareTranscript(
        fixture->audit.statement,
        fixture->audit.report_witnesses[0].observed_members,
        fixture->rosters[0].descriptor, 0,
        member.pro_tx_hash);
    share.authenticated_signature.key_proof = authorization.proof;
    const uint256 share_hash{GetPaymentAuditShareHash(
        fixture->genesis_hash, share.transcript)};
    scheduled_wots::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    const auto leaf_index{PaymentAuditLeafIndex(
        fixture->schedule, share.transcript.statement.commitment.subject_epoch,
        share.transcript.statement.commitment.seal_height,
        share.transcript.quorum_epoch)};
    BOOST_REQUIRE(leaf_index);
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, *leaf_index, message,
        share.authenticated_signature.signature));
    BOOST_REQUIRE(share.IsStructurallyValid());

    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    const auto check{PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule, share, fixture->rosters,
        AUTHORIZATION_MASK,
        &verification_error)};
    BOOST_REQUIRE(check);
    BOOST_CHECK(verification_error == PaymentAuditVerificationError::NONE);
    BOOST_CHECK_EQUAL(check->GetLeafIndex(), *leaf_index);
    BOOST_CHECK((*check)());

    const auto rosters{
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters)};
    auto prepared_context{PreparedPaymentAuditContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->audit.statement,
        fixture->seal, rosters, AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(prepared_context);
    BOOST_CHECK(prepared_context->RostersPtr() != rosters);
    auto prepared_check{PreparePaymentAuditShareVerification(
        share, *prepared_context, &verification_error)};
    BOOST_REQUIRE(prepared_check);
    BOOST_CHECK(prepared_check->GetPublicKey() == check->GetPublicKey());
    BOOST_CHECK_EQUAL(prepared_check->GetLeafIndex(), check->GetLeafIndex());
    BOOST_CHECK(prepared_check->GetMessageBytes() == check->GetMessageBytes());
    BOOST_CHECK(prepared_check->GetSignature() == check->GetSignature());
    BOOST_CHECK((*prepared_check)());

    auto bad_proof{share};
    bad_proof.authenticated_signature.key_proof.siblings[0].begin()[0] ^= 1;
    PaymentAuditVerificationError raw_error{
        PaymentAuditVerificationError::NONE};
    PaymentAuditVerificationError prepared_error{
        PaymentAuditVerificationError::NONE};
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule, bad_proof,
        fixture->rosters, AUTHORIZATION_MASK, &raw_error));
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        bad_proof, *prepared_context, &prepared_error));
    BOOST_CHECK(raw_error == PaymentAuditVerificationError::INVALID_CHILD_PROOF);
    BOOST_CHECK(prepared_error == raw_error);

    ShareCollectionError staged_error{ShareCollectionError::NONE};
    auto staged_collector{PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(staged_collector);
    auto pending_reservation{
        staged_collector->ReserveShareVerification(share, &staged_error)};
    BOOST_REQUIRE(pending_reservation);
    BOOST_CHECK(staged_error == ShareCollectionError::NONE);
    BOOST_CHECK(!staged_collector->ReserveShareVerification(
        bad_proof, &staged_error));
    BOOST_CHECK(staged_error == ShareCollectionError::DUPLICATE);
    PaymentAuditCollector::VerifyReservedShare(*pending_reservation);
    BOOST_CHECK(staged_collector->CompleteShareVerification(
                    std::move(*pending_reservation), &staged_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(staged_error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(staged_collector->ShareCounts()[0], 1U);
    auto competing_report{share};
    competing_report.transcript.reporter_observed_members[0] ^= 1;
    BOOST_CHECK(!staged_collector->ReserveShareVerification(
        competing_report, &staged_error));
    BOOST_CHECK(staged_error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(staged_collector->ShareCounts()[0], 1U);

    auto unverified_collector{
        PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(unverified_collector);
    auto unverified_reservation{
        unverified_collector->ReserveShareVerification(
            share, &staged_error)};
    BOOST_REQUIRE(unverified_reservation);
    BOOST_CHECK(unverified_collector->CompleteShareVerification(
                    std::move(*unverified_reservation), &staged_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(staged_error == ShareCollectionError::LOCAL_ERROR);
    auto released_reservation{
        unverified_collector->ReserveShareVerification(
            share, &staged_error)};
    BOOST_REQUIRE(released_reservation);
    PaymentAuditCollector::VerifyReservedShare(*released_reservation);
    BOOST_CHECK(unverified_collector->CompleteShareVerification(
                    std::move(*released_reservation), &staged_error) ==
                ShareCollectionResult::ACCEPTED);

    auto retry_collector{PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(retry_collector);
    auto invalid_signature{share};
    invalid_signature.authenticated_signature.signature.back() ^= 1;
    auto invalid_reservation{retry_collector->ReserveShareVerification(
        invalid_signature, &staged_error)};
    BOOST_REQUIRE(invalid_reservation);
    PaymentAuditCollector::VerifyReservedShare(*invalid_reservation);
    BOOST_CHECK(retry_collector->CompleteShareVerification(
                    std::move(*invalid_reservation), &staged_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(staged_error == ShareCollectionError::INVALID_SIGNATURE);

    auto proof_reservation{retry_collector->ReserveShareVerification(
        bad_proof, &staged_error)};
    BOOST_REQUIRE(proof_reservation);
    BOOST_CHECK(retry_collector->CompleteShareVerification(
                    std::move(*invalid_reservation), &staged_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(staged_error == ShareCollectionError::LOCAL_ERROR);
    BOOST_CHECK(!retry_collector->ReserveShareVerification(
        share, &staged_error));
    BOOST_CHECK(staged_error == ShareCollectionError::DUPLICATE);
    PaymentAuditCollector::VerifyReservedShare(*proof_reservation);
    BOOST_CHECK(retry_collector->CompleteShareVerification(
                    std::move(*proof_reservation), &staged_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(staged_error == ShareCollectionError::INVALID_CHILD_PROOF);
    BOOST_CHECK_EQUAL(retry_collector->ShareCounts()[0], 0U);

    auto valid_reservation{retry_collector->ReserveShareVerification(
        share, &staged_error)};
    BOOST_REQUIRE(valid_reservation);
    PaymentAuditCollector::VerifyReservedShare(*valid_reservation);
    BOOST_CHECK(retry_collector->CompleteShareVerification(
                    std::move(*valid_reservation), &staged_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(staged_error == ShareCollectionError::NONE);

    auto old_collector{PaymentAuditCollector::Create(prepared_context)};
    auto replacement_collector{
        PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(old_collector);
    BOOST_REQUIRE(replacement_collector);
    auto old_reservation{old_collector->ReserveShareVerification(
        share, &staged_error)};
    BOOST_REQUIRE(old_reservation);
    old_collector.reset();
    auto replacement_reservation{
        replacement_collector->ReserveShareVerification(
            share, &staged_error)};
    BOOST_REQUIRE(replacement_reservation);
    PaymentAuditCollector::VerifyReservedShare(*old_reservation);
    BOOST_CHECK(replacement_collector->CompleteShareVerification(
                    std::move(*old_reservation), &staged_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(staged_error == ShareCollectionError::LOCAL_ERROR);
    BOOST_CHECK(!replacement_collector->ReserveShareVerification(
        share, &staged_error));
    BOOST_CHECK(staged_error == ShareCollectionError::DUPLICATE);
    PaymentAuditCollector::VerifyReservedShare(*replacement_reservation);
    BOOST_CHECK(replacement_collector->CompleteShareVerification(
                    std::move(*replacement_reservation), &staged_error) ==
                ShareCollectionResult::ACCEPTED);

    auto lifetime_context{PreparedPaymentAuditContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->audit.statement,
        fixture->seal, rosters, AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(lifetime_context);
    std::weak_ptr<const PreparedPaymentAuditContext> retained_reservation{
        lifetime_context};
    auto lifetime_collector{
        PaymentAuditCollector::Create(lifetime_context)};
    BOOST_REQUIRE(lifetime_collector);
    auto lifetime_reservation{
        lifetime_collector->ReserveShareVerification(share, &staged_error)};
    BOOST_REQUIRE(lifetime_reservation);
    lifetime_context.reset();
    lifetime_collector.reset();
    BOOST_CHECK(!retained_reservation.expired());
    PaymentAuditCollector::VerifyReservedShare(*lifetime_reservation);
    lifetime_reservation.reset();
    BOOST_CHECK(retained_reservation.expired());

    auto unknown_quorum{share};
    unknown_quorum.transcript.quorum_base_hash = NonNullHash(91'002);
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule, unknown_quorum,
        fixture->rosters, AUTHORIZATION_MASK, &raw_error));
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        unknown_quorum, *prepared_context, &prepared_error));
    BOOST_CHECK(raw_error == PaymentAuditVerificationError::INVALID_CONTEXT);
    BOOST_CHECK(prepared_error == raw_error);

    auto unauthorized_context_share{share};
    unauthorized_context_share.transcript.quorum_epoch =
        fixture->rosters.back().descriptor.epoch;
    unauthorized_context_share.transcript.quorum_base_hash =
        fixture->rosters.back().descriptor.base_hash;
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule,
        unauthorized_context_share, fixture->rosters, AUTHORIZATION_MASK,
        &raw_error));
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        unauthorized_context_share, *prepared_context, &prepared_error));
    BOOST_CHECK(raw_error == PaymentAuditVerificationError::INVALID_CONTEXT);
    BOOST_CHECK(prepared_error == raw_error);

    auto alternate_report{share};
    alternate_report.transcript.reporter_observed_members[0] &=
        static_cast<uint8_t>(~uint8_t{1});
    const uint256 alternate_report_hash{GetPaymentAuditShareHash(
        fixture->genesis_hash, alternate_report.transcript)};
    std::copy(alternate_report_hash.begin(), alternate_report_hash.end(),
              message.begin());
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, *leaf_index, message,
        alternate_report.authenticated_signature.signature));
    auto alternate_report_check{PreparePaymentAuditShareVerification(
        alternate_report, *prepared_context, &verification_error)};
    BOOST_REQUIRE(alternate_report_check);
    BOOST_CHECK((*alternate_report_check)());

    auto alternate_share{share};
    alternate_share.transcript.statement.commitment.subject_descriptor_hash
        .begin()[0] ^= 1;
    const uint256 alternate_hash{GetPaymentAuditShareHash(
        fixture->genesis_hash, alternate_share.transcript)};
    std::copy(alternate_hash.begin(), alternate_hash.end(), message.begin());
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, *leaf_index, message,
        alternate_share.authenticated_signature.signature));
    auto alternate_raw_check{PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule, alternate_share,
        fixture->rosters, AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(alternate_raw_check);
    BOOST_CHECK((*alternate_raw_check)());
    BOOST_CHECK(!PreparePaymentAuditShareVerification(
        alternate_share, *prepared_context, &verification_error));
    BOOST_CHECK(verification_error ==
                PaymentAuditVerificationError::INVALID_CONTEXT);

    auto mutable_rosters{
        std::make_shared<FrozenQuorumRosters>(fixture->rosters)};
    FrozenQuorumRostersPtr aliased_rosters{mutable_rosters};
    auto alias_safe_context{PreparedPaymentAuditContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->audit.statement,
        fixture->seal, aliased_rosters, AUTHORIZATION_MASK,
        &verification_error)};
    BOOST_REQUIRE(alias_safe_context);
    const auto alias_slot{alias_safe_context->FindQuorumSlot(share.transcript)};
    BOOST_REQUIRE(alias_slot);
    mutable_rosters->at(*alias_slot)
        .members.at(share.transcript.member_index)
        .pro_tx_hash = NonNullHash(91'001);
    auto alias_safe_check{PreparePaymentAuditShareVerification(
        share, *alias_safe_context, &verification_error)};
    BOOST_REQUIRE(alias_safe_check);
    BOOST_CHECK((*alias_safe_check)());

    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    auto wrong_scheduled_leaf{share};
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, static_cast<uint8_t>(*leaf_index - 1), message,
        wrong_scheduled_leaf.authenticated_signature.signature));
    const auto wrong_leaf_check{PreparePaymentAuditShareVerification(
        fixture->genesis_hash, fixture->schedule, wrong_scheduled_leaf,
        fixture->rosters, AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(wrong_leaf_check);
    BOOST_CHECK(!(*wrong_leaf_check)());

    std::weak_ptr<const PreparedPaymentAuditContext> retained_context{
        prepared_context};
    auto prepared_collector{PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(prepared_collector);
    prepared_context.reset();
    BOOST_CHECK(!retained_context.expired());
    ShareCollectionError prepared_collection_error{
        ShareCollectionError::NONE};
    BOOST_CHECK(prepared_collector->AddVerifiedShare(
                    wrong_scheduled_leaf, &prepared_collection_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(prepared_collection_error ==
                ShareCollectionError::INVALID_SIGNATURE);
    BOOST_CHECK_EQUAL(prepared_collector->ShareCounts()[0], 0U);
    BOOST_CHECK(prepared_collector->AddVerifiedShare(
                    share, &prepared_collection_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(prepared_collection_error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(prepared_collector->ShareCounts()[0], 1U);

    ShareCollectionError collection_error{
        ShareCollectionError::INVALID_ARGUMENT};
    auto collector{PaymentAuditCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->audit.statement,
        fixture->seal,
        rosters, AUTHORIZATION_MASK, &collection_error)};
    BOOST_REQUIRE(collector);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
    BOOST_CHECK(collector->AddVerifiedShare(share, &collection_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);

    auto unauthorized_share{share};
    unauthorized_share.transcript.quorum_epoch =
        fixture->rosters[3].descriptor.epoch;
    unauthorized_share.transcript.quorum_base_hash =
        fixture->rosters[3].descriptor.base_hash;
    unauthorized_share.transcript.member_pro_tx_hash =
        fixture->rosters[3].members[0].pro_tx_hash;
    BOOST_CHECK(collector->AddVerifiedShare(
                    unauthorized_share, &collection_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(collection_error == ShareCollectionError::INVALID_CONTEXT);

    llmq::CPQSignerJournal journal{
        m_path_root / "pq_payment_audit_signer_unauthorized"};
    PaymentAuditShareSigner signer{
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->schedule, journal};
    ChainLockSigningError signing_error{ChainLockSigningError::NONE};
    BOOST_CHECK(!signer.Sign(
        fixture->audit.statement,
        fixture->audit.report_witnesses[0].observed_members,
        fixture->seal, fixture->rosters, AUTHORIZATION_MASK, 3, 0,
        *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::INACTIVE_QUORUM);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, member.pro_tx_hash));

    auto skipped_statement{fixture->audit.statement};
    skipped_statement.seal_statement.previous_chainlock_height -= 5;
    auto skipped_seal{fixture->seal};
    skipped_seal.statement = skipped_statement.seal_statement;
    BOOST_REQUIRE(skipped_statement.IsStructurallyValid());
    BOOST_REQUIRE(skipped_seal.IsStructurallyValid());
    BOOST_CHECK(!signer.Sign(
        skipped_statement,
        fixture->audit.report_witnesses[0].observed_members,
        skipped_seal, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::INELIGIBLE_HEIGHT);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, member.pro_tx_hash));
}

BOOST_AUTO_TEST_CASE(audit_selection_cannot_exceed_predecessor_authorization)
{
    auto fixture{MakeFixture()};
    PaymentAuditVerificationError error{
        PaymentAuditVerificationError::NONE};
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        fixture->genesis_hash, fixture->schedule, fixture->audit,
        fixture->rosters,
        0b0011, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);

    fixture->audit.selected_quorum_mask = 0b1011;
    fixture->audit.signer_bitmaps[3] = fixture->audit.signer_bitmaps[2];
    fixture->audit.signer_bitmaps[2].fill(0);
    BOOST_REQUIRE(fixture->audit.IsStructurallyValid());
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        fixture->genesis_hash, fixture->schedule, fixture->audit,
        fixture->rosters,
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);
}

BOOST_AUTO_TEST_SUITE_END()
