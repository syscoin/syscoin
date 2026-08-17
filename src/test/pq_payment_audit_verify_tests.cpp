// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_store.h>

#include <crypto/sphincs_c11/sphincs_c11.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>

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
    FinalChainLock seal;
    FinalPaymentAudit audit;
    FrozenQuorumRosters rosters;
};

std::unique_ptr<AuditVerificationFixture> MakeFixture()
{
    auto fixture{std::make_unique<AuditVerificationFixture>()};
    fixture->seal.statement.height = 2'115;
    fixture->seal.statement.block_hash = NonNullHash(2);
    fixture->seal.statement.previous_chainlock_height = 2'110;
    fixture->seal.statement.previous_chainlock_hash = NonNullHash(3);
    fixture->seal.statement.quorum_context_hash = NonNullHash(4);
    fixture->seal.statement.payment_probation_state_hash = NonNullHash(5);
    fixture->seal.selected_quorum_mask = 0x07;
    fixture->seal.signatures.resize(FINAL_SIGNATURE_COUNT);

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = static_cast<uint32_t>(10 + slot);
        descriptor.base_height = static_cast<int32_t>(1'000 + 288 * slot);
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
    commitment.seed.epoch = 13;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        2'085, NonNullHash(30),
        BTCCursor{2'085, NonNullHash(31), NonNullHash(32)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(33);
    commitment.selected_row = 2;
    commitment.response_height = 2'050;
    commitment.deadline_height = 2'070;
    commitment.response_chainlock_logical_id = NonNullHash(33);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = fixture->seal.statement.height;
    commitment.subject_epoch = 13;
    commitment.subject_quorum_base_hash =
        fixture->rosters.back().descriptor.base_hash;
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
        fixture->genesis_hash, fixture->audit, fixture->rosters, &error)};
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

    auto wrong_context{MakeFixture()};
    wrong_context->rosters[0].descriptor.member_root.begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        wrong_context->genesis_hash, wrong_context->audit,
        wrong_context->rosters, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);

    auto wrong_proof{MakeFixture()};
    wrong_proof->audit.report_witnesses[0]
        .authenticated_signature.key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        wrong_proof->genesis_hash, wrong_proof->audit,
        wrong_proof->rosters, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CHILD_PROOF);
}

BOOST_AUTO_TEST_CASE(full_verifier_reports_invalid_signature_after_preflight)
{
    const auto fixture{MakeFixture()};
    PaymentAuditVerificationError error{PaymentAuditVerificationError::NONE};
    BOOST_CHECK(!VerifyFinalPaymentAudit(
        fixture->genesis_hash, fixture->audit, fixture->rosters,
        nullptr, &error));
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
            fixture->genesis_hash, preserved, fixture->rosters,
            nullptr, &error));
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
            fixture->genesis_hash, *loaded, fixture->rosters,
            nullptr, &error));
        BOOST_CHECK(error ==
                    PaymentAuditVerificationError::INVALID_SIGNATURE);
    }
}

BOOST_AUTO_TEST_CASE(real_c11_share_verifies_and_enters_collector)
{
    auto fixture{MakeFixture()};
    sphincs_c11::SecretSeed secret_seed{};
    sphincs_c11::PublicSeed public_seed{};
    for (std::size_t i{0}; i < secret_seed.size(); ++i) {
        secret_seed[i] = static_cast<uint8_t>(i + 1);
    }
    for (std::size_t i{0}; i < public_seed.size(); ++i) {
        public_seed[i] = static_cast<uint8_t>(0xa0 + i);
    }
    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(
        secret_seed, public_seed, public_key, secret_key));

    const auto& member{fixture->rosters[0].members[0]};
    auto authorization{test::MakeSyntheticChildAuthorization(
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->rosters[0].descriptor.epoch,
        sphincs_c11::SerializePublicKey(public_key), 90'001)};
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
    sphincs_c11::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    BOOST_REQUIRE(sphincs_c11::Sign(
        secret_key, message, share.authenticated_signature.signature));
    BOOST_REQUIRE(share.IsStructurallyValid());

    PaymentAuditVerificationError verification_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    const auto check{PreparePaymentAuditShareVerification(
        fixture->genesis_hash, share, fixture->rosters,
        &verification_error)};
    BOOST_REQUIRE(check);
    BOOST_CHECK(verification_error == PaymentAuditVerificationError::NONE);
    BOOST_CHECK((*check)());

    const auto rosters{
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters)};
    ShareCollectionError collection_error{
        ShareCollectionError::INVALID_ARGUMENT};
    auto collector{PaymentAuditCollector::Create(
        fixture->genesis_hash, fixture->audit.statement, fixture->seal,
        rosters, &collection_error)};
    BOOST_REQUIRE(collector);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
    BOOST_CHECK(collector->AddVerifiedShare(share, &collection_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_SUITE_END()
