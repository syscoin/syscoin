// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_payment_audit_collector.h>
#include <llmq/pq_payment_audit_signer.h>
#include <llmq/pq_payment_audit_store.h>
#include <llmq/pq_payment_audit_verify.h>

#include <crypto/scheduled_wots/scheduled_wots.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

static_assert(!std::is_default_constructible_v<
              CollectedPaymentAuditFinalization>);
static_assert(!std::is_copy_constructible_v<
              CollectedPaymentAuditFinalization>);
static_assert(!std::is_constructible_v<
              CollectedPaymentAuditFinalization,
              FinalPaymentAudit,
              PreparedPaymentAuditContextPtr>);
static_assert(std::is_same_v<
              decltype(std::declval<const CollectedPaymentAuditFinalization&>()
                           .Certificate()),
              const FinalPaymentAudit&>);

namespace llmq_tests {

class PaymentAuditCollectorTestAccess {
public:
    static bool InsertFinalizedWitnesses(
        PaymentAuditCollector& collector,
        const FinalPaymentAudit& audit)
    {
        if (!audit.IsStructurallyValid() ||
            audit.statement != collector.m_context->Statement()) {
            return false;
        }
        std::size_t offset{0};
        for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
            for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
                const bool selected{
                    (audit.signer_bitmaps[slot][member / 8] &
                     static_cast<uint8_t>(uint8_t{1} << (member % 8))) != 0};
                if (!selected) continue;
                if (offset >= audit.report_witnesses.size()) return false;
                collector.m_shares[slot].emplace(
                    static_cast<uint16_t>(member),
                    audit.report_witnesses[offset++]);
            }
        }
        return offset == audit.report_witnesses.size();
    }
};

} // namespace llmq_tests

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

void ClearMember(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] &=
        static_cast<uint8_t>(~static_cast<uint8_t>(
            uint8_t{1} << (member % 8)));
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

struct ResponseVerificationFixture {
    uint256 genesis_hash{NonNullHash(40'001)};
    PaymentAuditScheduleConfig schedule{
        ChainLockScheduleConfig{.epoch_origin = 0},
        BTCCScheduleConfig{.candidate_origin = 865}};
    ChainLockStatement statement;
    FrozenQuorumRosters rosters;
    PaymentAuditResponse response;
    PaymentAuditHave expected;
    PreparedChainLockContextPtr context;
};

std::unique_ptr<ResponseVerificationFixture> MakeResponseFixture()
{
    auto fixture{std::make_unique<ResponseVerificationFixture>()};
    const auto audit_schedule{
        BuildPaymentAuditEpochSchedule(fixture->schedule, SUBJECT_EPOCH)};
    BOOST_REQUIRE(audit_schedule);
    fixture->statement.height = audit_schedule->rows[0].response_height;
    fixture->statement.block_hash = NonNullHash(40'002);
    fixture->statement.previous_chainlock_height =
        fixture->statement.height - PQ_CL_PERIOD;
    fixture->statement.previous_chainlock_hash = NonNullHash(40'003);
    fixture->statement.accepted_btcc_cursor = BTCCursor{
        fixture->statement.height, NonNullHash(40'004),
        NonNullHash(40'005)};
    fixture->statement.btcc_advance = BTCCAdvance::ADVANCE;
    fixture->statement.payment_probation_state_hash = NonNullHash(40'006);

    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t byte{0}; byte < seed.size(); ++byte) {
        seed[byte] = static_cast<uint8_t>(byte + 9);
    }
    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));

    const auto active_epochs{ActiveEpochsAtHeight(
        fixture->schedule.chainlock, fixture->statement.height)};
    BOOST_REQUIRE(active_epochs);
    BOOST_REQUIRE_EQUAL(active_epochs->back().epoch, SUBJECT_EPOCH);
    ChildKeyProof subject_key_proof;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = (*active_epochs)[slot].epoch;
        descriptor.base_height = (*active_epochs)[slot].base_height;
        descriptor.base_hash = NonNullHash(40'100 + slot);
        descriptor.snapshot_height = descriptor.base_height - 100;
        descriptor.snapshot_hash = NonNullHash(40'200 + slot);
        SetFirstMembers(descriptor.valid_members, QUORUM_MIN_VALID);
        descriptor.valid_count = QUORUM_MIN_VALID;
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            auto& frozen{roster.members[member]};
            frozen.pro_tx_hash =
                NonNullHash(41'000 + slot * QUORUM_SIZE + member);
            frozen.eligible = member < QUORUM_MIN_VALID;
            if (!frozen.eligible) continue;
            ChildPublicKey child_key{UniqueChildKey(slot, member)};
            if (slot == ACTIVE_QUORUMS - 1 && member == 0) {
                child_key = public_key;
            }
            const auto authorization{test::MakeSyntheticChildAuthorization(
                fixture->genesis_hash, frozen.pro_tx_hash,
                descriptor.epoch, child_key,
                1 + slot * QUORUM_SIZE + member)};
            frozen.child_root = authorization.record;
            if (slot == ACTIVE_QUORUMS - 1 && member == 0) {
                subject_key_proof = authorization.proof;
            }
        }
        descriptor.member_root =
            ComputeQuorumMemberRoot(fixture->genesis_hash, roster);
        descriptor.child_key_root =
            ComputeQuorumChildKeyRoot(fixture->genesis_hash, roster);
    }
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    fixture->statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, fixture->statement.height,
        fixture->statement.block_hash, descriptors);
    BOOST_REQUIRE(fixture->statement.IsStructurallyValid());

    const auto& subject{fixture->rosters.back()};
    FinalChainLock shell;
    shell.statement = fixture->statement;
    fixture->response.epoch = SUBJECT_EPOCH;
    fixture->response.row_index = 0;
    fixture->response.subject_descriptor_hash =
        GetPaymentAuditDescriptorHash(fixture->genesis_hash,
                                      subject.descriptor);
    fixture->response.response.transcript = BuildChainLockShareTranscript(
        shell, subject.descriptor, 0,
        subject.members[0].pro_tx_hash);
    fixture->response.response.authenticated_signature.key_proof =
        subject_key_proof;
    const uint256 share_hash{GetChainLockShareHash(
        fixture->genesis_hash, fixture->response.response.transcript)};
    scheduled_wots::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    const auto leaf_index{ChainLockLeafIndex(
        fixture->schedule.chainlock, subject.descriptor.epoch,
        fixture->statement.height)};
    BOOST_REQUIRE(leaf_index);
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, *leaf_index, message,
        fixture->response.response.authenticated_signature.signature));
    BOOST_REQUIRE(fixture->response.IsStructurallyValid());

    fixture->expected.epoch = fixture->response.epoch;
    fixture->expected.row_index = fixture->response.row_index;
    fixture->expected.response_height = fixture->statement.height;
    fixture->expected.response_chainlock_logical_id =
        GetLogicalChainLockId(fixture->genesis_hash, fixture->statement);
    fixture->expected.subject_descriptor_hash =
        fixture->response.subject_descriptor_hash;
    BOOST_REQUIRE(fixture->expected.IsStructurallyValid());
    fixture->context = PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule.chainlock,
        fixture->statement,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        0b1111);
    BOOST_REQUIRE(fixture->context);
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

BOOST_AUTO_TEST_CASE(final_preparation_reuses_verified_seal_rosters)
{
    const auto fixture{MakeFixture()};
    const auto rosters{
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters)};
    ChainLockVerificationError roster_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    const uint64_t capability_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, rosters, &roster_error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(roster_error == ChainLockVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          capability_hashes_before,
                      8'184U);

    PaymentAuditVerificationError error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    const uint64_t prepared_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto prepared{PrepareFinalPaymentAuditVerification(
        fixture->schedule, fixture->audit, roster_set,
        AUTHORIZATION_MASK, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(error == PaymentAuditVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_hashes_before);

    const uint64_t raw_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto raw{PrepareFinalPaymentAuditVerification(
        fixture->genesis_hash, fixture->schedule, fixture->audit,
        fixture->rosters, AUTHORIZATION_MASK, &error)};
    BOOST_REQUIRE(raw);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          raw_hashes_before,
                      8'184U);
    BOOST_REQUIRE_EQUAL(prepared->checks.size(), raw->checks.size());
    for (std::size_t i{0}; i < prepared->checks.size(); ++i) {
        BOOST_CHECK(prepared->checks[i].GetPublicKey() ==
                    raw->checks[i].GetPublicKey());
        BOOST_CHECK_EQUAL(prepared->checks[i].GetLeafIndex(),
                          raw->checks[i].GetLeafIndex());
        BOOST_CHECK(prepared->checks[i].GetMessageBytes() ==
                    raw->checks[i].GetMessageBytes());
        BOOST_CHECK(prepared->checks[i].GetSignature() ==
                    raw->checks[i].GetSignature());
    }

    const uint64_t rejection_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto bad_context{fixture->audit};
    bad_context.statement.seal_statement.quorum_context_hash.begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        fixture->schedule, bad_context, roster_set,
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);

    auto bad_selection{fixture->audit};
    bad_selection.selected_quorum_mask = 0b1011;
    bad_selection.signer_bitmaps[3] = bad_selection.signer_bitmaps[2];
    bad_selection.signer_bitmaps[2].fill(0);
    BOOST_REQUIRE(bad_selection.IsStructurallyValid());
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        fixture->schedule, bad_selection, roster_set,
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);

    auto bad_proof{fixture->audit};
    bad_proof.report_witnesses[0]
        .authenticated_signature.key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        fixture->schedule, bad_proof, roster_set,
        AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CHILD_PROOF);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      rejection_hashes_before);

    auto underfilled{MakeFixture()};
    auto& underfilled_roster{underfilled->rosters[0]};
    constexpr std::size_t LAST_VALID_MEMBER{QUORUM_MIN_VALID - 1};
    underfilled_roster.members[LAST_VALID_MEMBER].eligible = false;
    ClearMember(underfilled_roster.descriptor.valid_members,
                LAST_VALID_MEMBER);
    underfilled_roster.descriptor.valid_count = QUORUM_MIN_VALID - 1;
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = underfilled->rosters[slot].descriptor;
    }
    underfilled->audit.statement.seal_statement.quorum_context_hash =
        GetQuorumContextHash(
            underfilled->genesis_hash,
            underfilled->audit.statement.seal_statement.height,
            underfilled->audit.statement.seal_statement.block_hash,
            descriptors);
    const auto underfilled_rosters{
        std::make_shared<const FrozenQuorumRosters>(underfilled->rosters)};
    const auto underfilled_set{VerifiedRosterSet::Create(
        underfilled->genesis_hash, underfilled_rosters, &roster_error)};
    BOOST_REQUIRE(underfilled_set);
    const uint64_t underfilled_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(!PrepareFinalPaymentAuditVerification(
        underfilled->schedule, underfilled->audit,
        underfilled_set, AUTHORIZATION_MASK, &error));
    BOOST_CHECK(error == PaymentAuditVerificationError::INVALID_CONTEXT);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      underfilled_hashes_before);
}

BOOST_AUTO_TEST_CASE(collected_finalization_binds_exact_bytes_and_context)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    const auto rosters{
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters)};
    ChainLockVerificationError roster_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, rosters, &roster_error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(roster_error == ChainLockVerificationError::NONE);
    PaymentAuditVerificationError audit_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    auto prepared_context{PreparedPaymentAuditContext::Create(
        fixture->schedule, fixture->audit.statement, fixture->seal,
        roster_set, AUTHORIZATION_MASK, &audit_error)};
    BOOST_REQUIRE(prepared_context);
    BOOST_CHECK(audit_error == PaymentAuditVerificationError::NONE);
    std::weak_ptr<const PreparedPaymentAuditContext> retained_context{
        prepared_context};
    auto collector{PaymentAuditCollector::Create(prepared_context)};
    BOOST_REQUIRE(collector);
    const std::size_t empty_collector_bytes{collector->MemoryUsage()};
    BOOST_CHECK_GE(empty_collector_bytes, sizeof(PaymentAuditCollector));
    prepared_context.reset();

    BOOST_CHECK(!collector->FinalizeCollection());
    BOOST_REQUIRE(
        llmq_tests::PaymentAuditCollectorTestAccess::
            InsertFinalizedWitnesses(*collector, fixture->audit));
    BOOST_CHECK_GT(collector->MemoryUsage(), empty_collector_bytes);
    BOOST_REQUIRE(collector->IsComplete());
    const auto collected{collector->FinalizeCollection()};
    BOOST_REQUIRE(collected);
    BOOST_CHECK(collected->ContextPtr() == retained_context.lock());
    BOOST_CHECK(collected->Certificate() == fixture->audit);

    auto detached_copy{collected->Certificate()};
    detached_copy.report_witnesses[0].observed_members[0] ^= 1;
    BOOST_CHECK(collected->Certificate() != detached_copy);
    collector.reset();
    BOOST_CHECK(!retained_context.expired());
    BOOST_CHECK(collected->ContextPtr() == retained_context.lock());
}

BOOST_AUTO_TEST_CASE(verified_response_rosters_bind_subject_without_rebuild)
{
    const auto fixture{MakeResponseFixture()};
    ChainLockVerificationError roster_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &roster_error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(roster_error == ChainLockVerificationError::NONE);

    const auto& subject{roster_set->Rosters().back().descriptor};
    PaymentAuditCommitment commitment;
    commitment.subject_epoch = subject.epoch;
    commitment.subject_quorum_base_hash = subject.base_hash;
    commitment.subject_descriptor_hash =
        GetPaymentAuditDescriptorHash(fixture->genesis_hash, subject);
    commitment.subject_valid_members = subject.valid_members;

    const uint64_t hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(MatchesVerifiedPaymentAuditSubject(
        commitment, *roster_set));
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      hashes_before);

    const auto expect_mismatch = [&](auto mutate) {
        auto mismatched{commitment};
        mutate(mismatched);
        BOOST_CHECK(!MatchesVerifiedPaymentAuditSubject(
            mismatched, *roster_set));
        BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                          hashes_before);
    };
    expect_mismatch([](auto& mismatched) {
        ++mismatched.subject_epoch;
    });
    expect_mismatch([](auto& mismatched) {
        mismatched.subject_quorum_base_hash.begin()[0] ^= 1;
    });
    expect_mismatch([](auto& mismatched) {
        mismatched.subject_valid_members[0] ^= 1;
    });
    expect_mismatch([](auto& mismatched) {
        mismatched.subject_descriptor_hash.begin()[0] ^= 1;
    });
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

BOOST_AUTO_TEST_CASE(response_prepared_context_matches_raw_and_is_exact)
{
    const auto fixture{MakeResponseFixture()};
    PaymentAuditVerificationError raw_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    PaymentAuditVerificationError prepared_error{
        PaymentAuditVerificationError::INVALID_ARGUMENT};
    const auto raw_check{PreparePaymentAuditResponseVerification(
        fixture->genesis_hash, fixture->schedule.chainlock,
        fixture->response, fixture->expected, fixture->rosters, 0b1111,
        &raw_error)};
    const auto prepared_check{PreparePaymentAuditResponseVerification(
        fixture->response, fixture->expected, *fixture->context,
        &prepared_error)};
    BOOST_REQUIRE(raw_check);
    BOOST_REQUIRE(prepared_check);
    BOOST_CHECK(raw_error == PaymentAuditVerificationError::NONE);
    BOOST_CHECK(prepared_error == raw_error);
    BOOST_CHECK(raw_check->GetPublicKey() ==
                prepared_check->GetPublicKey());
    BOOST_CHECK_EQUAL(raw_check->GetLeafIndex(),
                      prepared_check->GetLeafIndex());
    BOOST_CHECK(raw_check->GetMessageBytes() ==
                prepared_check->GetMessageBytes());
    BOOST_CHECK(raw_check->GetSignature() ==
                prepared_check->GetSignature());
    BOOST_CHECK((*raw_check)());
    BOOST_CHECK((*prepared_check)());
    BOOST_CHECK(MatchesPaymentAuditResponseContext(
        fixture->expected, *fixture->context, fixture->statement));

    auto finalized_keep{fixture->statement};
    finalized_keep.accepted_btcc_cursor =
        finalized_keep.previous_btcc_cursor;
    finalized_keep.btcc_advance = BTCCAdvance::KEEP;
    BOOST_REQUIRE(finalized_keep.IsStructurallyValid());
    BOOST_CHECK(!MatchesPaymentAuditResponseContext(
        fixture->expected, *fixture->context, finalized_keep));
    auto mismatched_final{fixture->statement};
    mismatched_final.payment_probation_state_hash = NonNullHash(49'000);
    BOOST_REQUIRE(mismatched_final.IsStructurallyValid());
    BOOST_CHECK(!MatchesPaymentAuditResponseContext(
        fixture->expected, *fixture->context, mismatched_final));

    auto bad_proof{fixture->response};
    bad_proof.response.authenticated_signature.key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PreparePaymentAuditResponseVerification(
        fixture->genesis_hash, fixture->schedule.chainlock, bad_proof,
        fixture->expected, fixture->rosters, 0b1111, &raw_error));
    BOOST_CHECK(!PreparePaymentAuditResponseVerification(
        bad_proof, fixture->expected, *fixture->context,
        &prepared_error));
    BOOST_CHECK(raw_error ==
                PaymentAuditVerificationError::INVALID_CHILD_PROOF);
    BOOST_CHECK(prepared_error == raw_error);

    auto alternate_statement{fixture->statement};
    alternate_statement.payment_probation_state_hash = NonNullHash(49'001);
    auto alternate_context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule.chainlock,
        alternate_statement,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        0b1111)};
    BOOST_REQUIRE(alternate_context);
    BOOST_CHECK(!PreparePaymentAuditResponseVerification(
        fixture->response, fixture->expected, *alternate_context,
        &prepared_error));
    BOOST_CHECK(prepared_error ==
                PaymentAuditVerificationError::INVALID_CONTEXT);

    auto mutable_rosters{
        std::make_shared<FrozenQuorumRosters>(fixture->rosters)};
    FrozenQuorumRostersPtr aliased_rosters{mutable_rosters};
    auto alias_safe_context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule.chainlock,
        fixture->statement, aliased_rosters, 0b1111)};
    BOOST_REQUIRE(alias_safe_context);
    mutable_rosters->back().members[0].pro_tx_hash = NonNullHash(49'002);
    const auto alias_safe_check{PreparePaymentAuditResponseVerification(
        fixture->response, fixture->expected, *alias_safe_context,
        &prepared_error)};
    BOOST_REQUIRE(alias_safe_check);
    BOOST_CHECK((*alias_safe_check)());
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
    ChainLockVerificationError roster_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    const uint64_t root_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, rosters, &roster_error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(roster_error == ChainLockVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          root_hashes_before,
                      8'184U);
    const uint64_t prepared_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto prepared_context{PreparedPaymentAuditContext::Create(
        fixture->schedule, fixture->audit.statement, fixture->seal,
        roster_set, AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(prepared_context);
    BOOST_CHECK(prepared_context->RosterSetPtr() == roster_set);
    BOOST_CHECK(prepared_context->RostersPtr() == roster_set->RostersPtr());
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_hashes_before);
    const uint64_t prepared_share_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto prepared_check{PreparePaymentAuditShareVerification(
        share, *prepared_context, &verification_error)};
    BOOST_REQUIRE(prepared_check);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_share_hashes_before);
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
    BOOST_CHECK(staged_collector->GetPreparedContext() == prepared_context);
    auto pending_reservation{
        staged_collector->ReserveShareVerification(share, &staged_error)};
    BOOST_REQUIRE(pending_reservation);
    BOOST_CHECK(staged_error == ShareCollectionError::NONE);
    BOOST_CHECK(!staged_collector->HasAcceptedShare(share.transcript));
    BOOST_CHECK(!staged_collector->ReserveShareVerification(
        bad_proof, &staged_error));
    BOOST_CHECK(staged_error == ShareCollectionError::DUPLICATE);
    PaymentAuditCollector::VerifyReservedShare(*pending_reservation);
    BOOST_CHECK(staged_collector->CompleteShareVerification(
                    std::move(*pending_reservation), &staged_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(staged_error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(staged_collector->ShareCounts()[0], 1U);
    BOOST_CHECK(staged_collector->HasAcceptedShare(share.transcript));
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

    const uint64_t shared_context_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto signer_context{PreparedPaymentAuditContext::Create(
        fixture->schedule, fixture->audit.statement, fixture->seal,
        roster_set,
        AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(signer_context);
    BOOST_CHECK(signer_context->RosterSetPtr() == roster_set);

    llmq::CPQSignerJournal success_journal{
        m_path_root / "pq_payment_audit_signer_success"};
    ChainLockShareSigner seal_signer{
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->schedule.chainlock, success_journal};
    ChainLockVerificationError seal_context_error{
        ChainLockVerificationError::NONE};
    auto seal_context{PreparedChainLockContext::Create(
        fixture->schedule.chainlock, fixture->seal.statement, roster_set,
        AUTHORIZATION_MASK,
        &seal_context_error)};
    BOOST_REQUIRE(seal_context);
    BOOST_CHECK(seal_context_error == ChainLockVerificationError::NONE);
    BOOST_CHECK(seal_context->RosterSetPtr() == roster_set);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      shared_context_hashes_before);
    BOOST_REQUIRE(seal_signer.Sign(
        *seal_context, 0, 0, *secret_key, authorization.proof,
        std::nullopt).share);
    const auto seal_lock{success_journal.GetBranchLock(
        fixture->genesis_hash, member.pro_tx_hash)};
    BOOST_REQUIRE(seal_lock);

    PaymentAuditShareSigner success_signer{
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->schedule, success_journal};
    ChainLockSigningError signing_error{ChainLockSigningError::NONE};
    BOOST_CHECK(!success_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::JOURNAL_CONFLICT);
    auto wrong_seal_lock{*seal_lock};
    wrong_seal_lock.statement_hash.begin()[0] ^= 1;
    BOOST_CHECK(!success_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, wrong_seal_lock,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::JOURNAL_CONFLICT);

    const auto signed_audit{success_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, seal_lock,
        &signing_error)};
    BOOST_REQUIRE(signed_audit.share);
    BOOST_CHECK(!signed_audit.replayed);
    BOOST_CHECK(signing_error == ChainLockSigningError::NONE);
    BOOST_CHECK(signed_audit.share->transcript == share.transcript);
    BOOST_CHECK(signed_audit.share->authenticated_signature ==
                share.authenticated_signature);
    const auto signed_replay{success_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, seal_lock,
        &signing_error)};
    BOOST_REQUIRE(signed_replay.share);
    BOOST_CHECK(signed_replay.replayed);
    BOOST_CHECK(*signed_replay.share == *signed_audit.share);

    auto competing_report_bitmap{
        fixture->audit.report_witnesses[0].observed_members};
    competing_report_bitmap[0] ^= 1;
    BOOST_CHECK(!success_signer.Sign(
        *signer_context, competing_report_bitmap, 0, 0, *secret_key,
        authorization.proof, seal_lock, &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::JOURNAL_CONFLICT);

    llmq::CPQSignerJournal journal{
        m_path_root / "pq_payment_audit_signer_unauthorized"};
    PaymentAuditShareSigner signer{
        fixture->genesis_hash, member.pro_tx_hash,
        fixture->schedule, journal};
    BOOST_CHECK(!signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        3, 0,
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
    auto skipped_context{PreparedPaymentAuditContext::Create(
        fixture->genesis_hash, fixture->schedule, skipped_statement,
        skipped_seal, rosters, AUTHORIZATION_MASK,
        &verification_error)};
    BOOST_REQUIRE(skipped_context);
    BOOST_CHECK(!signer.Sign(
        *skipped_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0,
        *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::INELIGIBLE_HEIGHT);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, member.pro_tx_hash));

    PaymentAuditShareSigner wrong_genesis_signer{
        NonNullHash(92'001), member.pro_tx_hash,
        fixture->schedule, journal};
    BOOST_CHECK(!wrong_genesis_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::INVALID_CONTEXT);

    auto other_schedule{fixture->schedule};
    other_schedule.chainlock.epoch_origin = 1440;
    other_schedule.btcc.candidate_origin += 1440;
    BOOST_REQUIRE(other_schedule.IsValid());
    PaymentAuditShareSigner wrong_schedule_signer{
        fixture->genesis_hash, member.pro_tx_hash,
        other_schedule, journal};
    BOOST_CHECK(!wrong_schedule_signer.Sign(
        *signer_context,
        fixture->audit.report_witnesses[0].observed_members,
        0, 0, *secret_key, authorization.proof, std::nullopt,
        &signing_error).share);
    BOOST_CHECK(signing_error == ChainLockSigningError::INVALID_CONTEXT);
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
