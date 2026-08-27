// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>

#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace llmq_tests {

class ChainLockCollectorTestAccess {
public:
    static void Insert(ChainLockCollector& collector,
                       std::size_t quorum_slot,
                       std::size_t count,
        uint8_t tag)
    {
        for (std::size_t member{0}; member < count; ++member) {
            AuthenticatedChildSignature signature;
            signature.key_proof.public_key[0] = 1;
            signature.signature[0] = tag;
            signature.signature[1] = static_cast<uint8_t>(member);
            signature.signature[2] = static_cast<uint8_t>(member >> 8);
            collector.m_shares[quorum_slot].emplace(
                static_cast<uint16_t>(member), std::move(signature));
        }
    }
};

} // namespace llmq_tests

namespace {

constexpr uint8_t FULL_AUTHORIZATION_MASK{0b1111};

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
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

ChildPublicKey FakeChildKey(std::size_t slot, std::size_t member)
{
    ChildPublicKey key{};
    const uint64_t value{1 + slot * QUORUM_SIZE + member};
    key[0] = 0xc1;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        key[1 + byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    return key;
}

struct CollectorFixture {
    uint256 genesis_hash{NonNullHash(7001)};
    ChainLockScheduleConfig schedule{.epoch_origin = 0};
    ChainLockStatement statement;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    std::optional<scheduled_wots::SecretKey> member_secret_key;
    ChildKeyProof member_key_proof;
};

std::unique_ptr<CollectorFixture> MakeFixture()
{
    auto fixture{std::make_unique<CollectorFixture>()};
    fixture->statement.height = 2000;
    fixture->statement.block_hash = NonNullHash(7100);
    fixture->statement.previous_chainlock_height = 1995;
    fixture->statement.previous_chainlock_hash = NonNullHash(7099);
    fixture->statement.payment_probation_state_hash = NonNullHash(7098);

    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = i + 1;
    fixture->member_secret_key = scheduled_wots::GenerateSecretKey(seed);
    BOOST_REQUIRE(fixture->member_secret_key);
    scheduled_wots::PublicKey member_public_key{};
    BOOST_REQUIRE(fixture->member_secret_key->GetPublicKey(member_public_key));

    const auto active_epochs{
        ActiveEpochsAtHeight(fixture->schedule, fixture->statement.height)};
    BOOST_REQUIRE(active_epochs);

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = (*active_epochs)[slot].epoch;
        descriptor.base_height = (*active_epochs)[slot].base_height;
        descriptor.base_hash = NonNullHash(7200 + slot);
        descriptor.snapshot_height = descriptor.base_height - 144;
        descriptor.snapshot_hash = NonNullHash(7300 + slot);

        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            auto& roster_member{roster.members[member]};
            roster_member.pro_tx_hash = NonNullHash(10'000 + slot * QUORUM_SIZE + member);
            roster_member.eligible = member < QUORUM_MIN_VALID;
            if (!roster_member.eligible) continue;

            ChildPublicKey public_key{FakeChildKey(slot, member)};
            if (slot == 0 && member == 0) {
                public_key = member_public_key;
            }
            const auto authorization{
                test::MakeSyntheticChildAuthorization(
                    fixture->genesis_hash, roster_member.pro_tx_hash,
                    descriptor.epoch, public_key,
                    1 + slot * QUORUM_SIZE + member)};
            roster_member.child_root = authorization.record;
            if (slot == 0 && member == 0) {
                fixture->member_key_proof = authorization.proof;
            }
            SetBit(descriptor.valid_members, member);
        }
        descriptor.valid_count = QUORUM_MIN_VALID;
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
    return fixture;
}

ChainLockShare SignFirstShare(const CollectorFixture& fixture,
                              std::optional<uint8_t> leaf_override = std::nullopt)
{
    FinalChainLock shell;
    shell.statement = fixture.statement;
    ChainLockShare share;
    share.transcript = BuildChainLockShareTranscript(
        shell, fixture.rosters[0].descriptor, 0,
        fixture.rosters[0].members[0].pro_tx_hash);
    const uint256 share_hash{GetChainLockShareHash(
        fixture.genesis_hash, share.transcript)};
    scheduled_wots::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    const auto scheduled_leaf{ChainLockLeafIndex(
        fixture.schedule, fixture.rosters[0].descriptor.epoch,
        fixture.statement.height)};
    BOOST_REQUIRE(scheduled_leaf);
    BOOST_REQUIRE(fixture.member_secret_key);
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *fixture.member_secret_key, leaf_override.value_or(*scheduled_leaf), message,
        share.authenticated_signature.signature));
    share.authenticated_signature.key_proof = fixture.member_key_proof;
    return share;
}

FrozenQuorumRostersPtr ShareRosters(const CollectorFixture& fixture)
{
    return std::make_shared<const FrozenQuorumRosters>(fixture.rosters);
}

PreparedChainLockContextPtr PrepareContext(const CollectorFixture& fixture)
{
    return PreparedChainLockContext::Create(
        fixture.genesis_hash, fixture.schedule, fixture.statement,
        ShareRosters(fixture), FULL_AUTHORIZATION_MASK);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_collector_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(prepared_context_is_exact_reusable_and_owned)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    FrozenQuorumRostersPtr rosters{ShareRosters(*fixture)};
    ChainLockVerificationError verification_error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    auto context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        rosters, FULL_AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(context);
    BOOST_CHECK(verification_error == ChainLockVerificationError::NONE);
    BOOST_CHECK(context->RostersPtr() != rosters);

    const ChainLockShare share{SignFirstShare(*fixture)};
    auto raw_check{PrepareChainLockShareVerification(
        fixture->genesis_hash, fixture->schedule, share, *rosters,
        FULL_AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(raw_check);
    auto prepared_check{PrepareChainLockShareVerification(
        share, *context, &verification_error)};
    BOOST_REQUIRE(prepared_check);
    BOOST_CHECK(raw_check->GetPublicKey() == prepared_check->GetPublicKey());
    BOOST_CHECK_EQUAL(raw_check->GetLeafIndex(),
                      prepared_check->GetLeafIndex());
    BOOST_CHECK(raw_check->GetMessageBytes() ==
                prepared_check->GetMessageBytes());
    BOOST_CHECK(raw_check->GetSignature() == prepared_check->GetSignature());
    BOOST_CHECK((*prepared_check)());

    const auto expect_same_rejection{
        [&](const ChainLockShare& candidate,
            const PreparedChainLockContext& prepared,
            uint8_t authorization_mask,
            ChainLockVerificationError expected) {
            ChainLockVerificationError raw_error{
                ChainLockVerificationError::NONE};
            ChainLockVerificationError prepared_error{
                ChainLockVerificationError::NONE};
            BOOST_CHECK(!PrepareChainLockShareVerification(
                fixture->genesis_hash, fixture->schedule, candidate,
                *rosters, authorization_mask, &raw_error));
            BOOST_CHECK(!PrepareChainLockShareVerification(
                candidate, prepared, &prepared_error));
            BOOST_CHECK(raw_error == expected);
            BOOST_CHECK(prepared_error == raw_error);
        }};

    auto unknown_quorum{share};
    unknown_quorum.transcript.quorum_base_hash = NonNullHash(7995);
    expect_same_rejection(
        unknown_quorum, *context, FULL_AUTHORIZATION_MASK,
        ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto bad_proof{share};
    bad_proof.authenticated_signature.key_proof.siblings[0].begin()[0] ^= 1;
    expect_same_rejection(
        bad_proof, *context, FULL_AUTHORIZATION_MASK,
        ChainLockVerificationError::INVALID_CHILD_PROOF);

    constexpr uint8_t TRANSITION_AUTHORIZATION_MASK{0b0111};
    auto transition_context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        rosters, TRANSITION_AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(transition_context);
    auto unauthorized_quorum{share};
    unauthorized_quorum.transcript.quorum_epoch =
        rosters->back().descriptor.epoch;
    unauthorized_quorum.transcript.quorum_base_hash =
        rosters->back().descriptor.base_hash;
    expect_same_rejection(
        unauthorized_quorum, *transition_context,
        TRANSITION_AUTHORIZATION_MASK,
        ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto wrong_statement{share};
    wrong_statement.transcript.block_hash = NonNullHash(7998);
    BOOST_CHECK(!PrepareChainLockShareVerification(
        wrong_statement, *context, &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);

    auto alternate_statement{fixture->statement};
    alternate_statement.block_hash = NonNullHash(7997);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = (*rosters)[slot].descriptor;
    }
    alternate_statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, alternate_statement.height,
        alternate_statement.block_hash, descriptors);
    const auto original_statement{fixture->statement};
    fixture->statement = alternate_statement;
    const ChainLockShare alternate_share{SignFirstShare(*fixture)};
    fixture->statement = original_statement;
    auto alternate_context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule,
        alternate_statement, rosters, FULL_AUTHORIZATION_MASK,
        &verification_error)};
    BOOST_REQUIRE(alternate_context);
    BOOST_CHECK(alternate_context->RostersPtr() != rosters);

    auto alternate_raw_check{PrepareChainLockShareVerification(
        fixture->genesis_hash, fixture->schedule, alternate_share, *rosters,
        FULL_AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(alternate_raw_check);
    BOOST_CHECK((*alternate_raw_check)());
    BOOST_CHECK(!PrepareChainLockShareVerification(
        alternate_share, *context, &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
    auto alternate_prepared_check{PrepareChainLockShareVerification(
        alternate_share, *alternate_context, &verification_error)};
    BOOST_REQUIRE(alternate_prepared_check);
    BOOST_CHECK((*alternate_prepared_check)());

    ShareCollectionError alternate_collection_error{
        ShareCollectionError::NONE};
    auto exact_collector{ChainLockCollector::Create(context)};
    BOOST_REQUIRE(exact_collector);
    BOOST_CHECK(exact_collector->AddVerifiedShare(
                    alternate_share, &alternate_collection_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(alternate_collection_error ==
                ShareCollectionError::STATEMENT_MISMATCH);
    alternate_context.reset();

    auto mutable_rosters{std::make_shared<FrozenQuorumRosters>(*rosters)};
    FrozenQuorumRostersPtr aliased_rosters{mutable_rosters};
    auto alias_safe_context{PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        aliased_rosters, FULL_AUTHORIZATION_MASK, &verification_error)};
    BOOST_REQUIRE(alias_safe_context);
    const auto alias_slot{alias_safe_context->FindQuorumSlot(share.transcript)};
    BOOST_REQUIRE(alias_slot);
    mutable_rosters->at(*alias_slot)
        .members.at(share.transcript.member_index)
        .pro_tx_hash = NonNullHash(7996);
    auto alias_safe_check{PrepareChainLockShareVerification(
        share, *alias_safe_context, &verification_error)};
    BOOST_REQUIRE(alias_safe_check);
    BOOST_CHECK((*alias_safe_check)());

    auto bad_rosters{std::make_shared<FrozenQuorumRosters>(*rosters)};
    (*bad_rosters)[0].descriptor.member_root.begin()[0] ^= 1;
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        bad_rosters, FULL_AUTHORIZATION_MASK, &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::MEMBER_ROOT_MISMATCH);

    auto bad_statement{fixture->statement};
    bad_statement.quorum_context_hash.begin()[0] ^= 1;
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->genesis_hash, fixture->schedule, std::move(bad_statement),
        ShareRosters(*fixture), FULL_AUTHORIZATION_MASK,
        &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);

    std::weak_ptr<const PreparedChainLockContext> retained{context};
    auto collector{ChainLockCollector::Create(context)};
    BOOST_REQUIRE(collector);
    context.reset();
    rosters.reset();
    BOOST_CHECK(!retained.expired());
    ShareCollectionError collection_error{ShareCollectionError::NONE};
    BOOST_CHECK(collector->AddVerifiedShare(share, &collection_error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(collection_error == ShareCollectionError::NONE);
}

BOOST_AUTO_TEST_CASE(cloned_signer_cannot_add_quorum_weight)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    ShareCollectionError error{ShareCollectionError::INVALID_ARGUMENT};
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        ShareRosters(*fixture),
        FULL_AUTHORIZATION_MASK,
        &error)};
    BOOST_REQUIRE(collector);
    BOOST_CHECK(error == ShareCollectionError::NONE);

    const ChainLockShare share{SignFirstShare(*fixture)};
    const ChainLockShare cloned_share{SignFirstShare(*fixture)};
    BOOST_CHECK(cloned_share.transcript == share.transcript);
    BOOST_CHECK(cloned_share.authenticated_signature ==
                share.authenticated_signature);
    BOOST_CHECK_EQUAL(GetSerializeSize(share, PROTOCOL_VERSION),
                      ChainLockShare::WIRE_SIZE);
    BOOST_CHECK(collector->AddVerifiedShare(share, &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1);

    BOOST_CHECK(collector->AddVerifiedShare(cloned_share, &error) ==
                ShareCollectionResult::DUPLICATE);
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1);

    auto alternate_witness{share};
    alternate_witness.authenticated_signature.signature[0] ^= 1;
    BOOST_CHECK(collector->AddVerifiedShare(alternate_witness, &error) ==
                ShareCollectionResult::DUPLICATE);
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);

    // Slot deduplication must not hide a transcript that attributes the slot to
    // a different member.
    auto wrong_member{alternate_witness};
    wrong_member.transcript.member_pro_tx_hash = NonNullHash(9998);
    BOOST_CHECK(collector->AddVerifiedShare(wrong_member, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_MEMBER);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(pending_reservation_deduplicates_before_crypto)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
    BOOST_REQUIRE(collector);

    const ChainLockShare share{SignFirstShare(*fixture)};
    ShareCollectionError error{ShareCollectionError::INVALID_ARGUMENT};
    auto reservation{collector->ReserveShareVerification(share, &error)};
    BOOST_REQUIRE(reservation);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 0U);

    BOOST_CHECK(!collector->ReserveShareVerification(share, &error));
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    auto alternate_witness{share};
    alternate_witness.authenticated_signature.signature[0] ^= 1;
    BOOST_CHECK(!collector->ReserveShareVerification(
        alternate_witness, &error));
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 0U);

    ChainLockCollector::VerifyReservedShare(*reservation);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*reservation), &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(failed_reservation_releases_slot_for_valid_retry)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
    BOOST_REQUIRE(collector);

    const ChainLockShare valid{SignFirstShare(*fixture)};
    auto invalid_signature{valid};
    invalid_signature.authenticated_signature.signature.back() ^= 1;
    ShareCollectionError error{ShareCollectionError::NONE};
    auto reservation{
        collector->ReserveShareVerification(invalid_signature, &error)};
    BOOST_REQUIRE(reservation);
    ChainLockCollector::VerifyReservedShare(*reservation);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*reservation), &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_SIGNATURE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 0U);

    auto invalid_proof{valid};
    invalid_proof.authenticated_signature.key_proof.siblings[0]
        .begin()[0] ^= 1;
    auto proof_reservation{collector->ReserveShareVerification(
        invalid_proof, &error)};
    BOOST_REQUIRE(proof_reservation);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*reservation), &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::LOCAL_ERROR);
    BOOST_CHECK(!collector->ReserveShareVerification(valid, &error));
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    ChainLockCollector::VerifyReservedShare(*proof_reservation);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*proof_reservation), &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_CHILD_PROOF);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 0U);

    auto valid_reservation{
        collector->ReserveShareVerification(valid, &error)};
    BOOST_REQUIRE(valid_reservation);
    ChainLockCollector::VerifyReservedShare(*valid_reservation);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*valid_reservation), &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(reservation_survives_collector_replacement_without_aba)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto context{PrepareContext(*fixture)};
    BOOST_REQUIRE(context);

    auto old_collector{ChainLockCollector::Create(context)};
    auto new_collector{ChainLockCollector::Create(context)};
    BOOST_REQUIRE(old_collector);
    BOOST_REQUIRE(new_collector);
    const ChainLockShare share{SignFirstShare(*fixture)};
    ShareCollectionError error{ShareCollectionError::NONE};
    auto old_reservation{
        old_collector->ReserveShareVerification(share, &error)};
    BOOST_REQUIRE(old_reservation);
    old_collector.reset();

    auto new_reservation{
        new_collector->ReserveShareVerification(share, &error)};
    BOOST_REQUIRE(new_reservation);

    ChainLockCollector::VerifyReservedShare(*old_reservation);
    BOOST_CHECK(new_collector->CompleteShareVerification(
                    std::move(*old_reservation), &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::LOCAL_ERROR);
    BOOST_CHECK_EQUAL(new_collector->ShareCounts()[0], 0U);
    BOOST_CHECK(!new_collector->ReserveShareVerification(share, &error));
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);

    ChainLockCollector::VerifyReservedShare(*new_reservation);
    BOOST_CHECK(new_collector->CompleteShareVerification(
                    std::move(*new_reservation), &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(new_collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(reservation_retains_prepared_context)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto context{PrepareContext(*fixture)};
    BOOST_REQUIRE(context);
    std::weak_ptr<const PreparedChainLockContext> retained{context};
    auto collector{ChainLockCollector::Create(context)};
    BOOST_REQUIRE(collector);
    auto reservation{collector->ReserveShareVerification(
        SignFirstShare(*fixture))};
    BOOST_REQUIRE(reservation);

    context.reset();
    collector.reset();
    BOOST_CHECK(!retained.expired());
    ChainLockCollector::VerifyReservedShare(*reservation);
    reservation.reset();
    BOOST_CHECK(retained.expired());
}

BOOST_AUTO_TEST_CASE(rejects_wrong_statement_member_and_signature)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        ShareRosters(*fixture),
        FULL_AUTHORIZATION_MASK)};
    BOOST_REQUIRE(collector);
    const ChainLockShare valid{SignFirstShare(*fixture)};
    ShareCollectionError error{ShareCollectionError::NONE};

    auto wrong_statement{valid};
    wrong_statement.transcript.block_hash = NonNullHash(9999);
    BOOST_CHECK(collector->AddVerifiedShare(wrong_statement, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::STATEMENT_MISMATCH);

    auto wrong_member{valid};
    wrong_member.transcript.member_pro_tx_hash = NonNullHash(9998);
    BOOST_CHECK(collector->AddVerifiedShare(wrong_member, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_MEMBER);

    auto wrong_signature{valid};
    wrong_signature.authenticated_signature.signature.back() ^= 1;
    BOOST_CHECK(collector->AddVerifiedShare(wrong_signature, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_SIGNATURE);

    const auto scheduled_leaf{ChainLockLeafIndex(
        fixture->schedule, fixture->rosters[0].descriptor.epoch,
        fixture->statement.height)};
    BOOST_REQUIRE(scheduled_leaf);
    const ChainLockShare wrong_scheduled_leaf{
        SignFirstShare(*fixture, static_cast<uint8_t>(*scheduled_leaf + 1))};
    BOOST_CHECK(collector->AddVerifiedShare(wrong_scheduled_leaf, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_SIGNATURE);
}

BOOST_AUTO_TEST_CASE(invalid_impersonation_does_not_reserve_signer_slot)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        ShareRosters(*fixture),
        FULL_AUTHORIZATION_MASK)};
    BOOST_REQUIRE(collector);
    const ChainLockShare valid{SignFirstShare(*fixture)};
    auto invalid{valid};
    invalid.authenticated_signature.signature.back() ^= 1;
    ShareCollectionError error{ShareCollectionError::NONE};

    BOOST_CHECK(collector->AddVerifiedShare(invalid, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_SIGNATURE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 0U);

    BOOST_CHECK(collector->AddVerifiedShare(valid, &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(finalizes_exact_lowest_three_ready_quorums_canonically)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        ShareRosters(*fixture),
        FULL_AUTHORIZATION_MASK)};
    BOOST_REQUIRE(collector);

    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 0, QUORUM_THRESHOLD - 1, 0xa0);
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 1, QUORUM_THRESHOLD, 0xb1);
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 2, QUORUM_THRESHOLD, 0xc2);
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 3, QUORUM_THRESHOLD, 0xd3);
    BOOST_CHECK(collector->IsComplete());

    const auto final{collector->Finalize()};
    BOOST_REQUIRE(final);
    BOOST_CHECK(final->IsStructurallyValid());
    BOOST_CHECK_EQUAL(final->selected_quorum_mask, 0b1110);
    BOOST_CHECK_EQUAL(final->signatures.size(), FINAL_SIGNATURE_COUNT);
    BOOST_CHECK_EQUAL(final->signatures[0].signature[0], 0xb1);
    BOOST_CHECK_EQUAL(
        final->signatures[QUORUM_THRESHOLD].signature[0], 0xc2);
    BOOST_CHECK_EQUAL(
        final->signatures[2 * QUORUM_THRESHOLD].signature[0], 0xd3);
    BOOST_CHECK(!final->SignatureOffset(0, 0));
    BOOST_CHECK_EQUAL(*final->SignatureOffset(3, QUORUM_THRESHOLD - 1),
                      FINAL_SIGNATURE_COUNT - 1);
}

BOOST_AUTO_TEST_CASE(one_transition_ignores_and_rejects_newest_roster)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->schedule, fixture->statement,
        ShareRosters(*fixture),
        0b0111)};
    BOOST_REQUIRE(collector);

    auto unauthorized{SignFirstShare(*fixture)};
    unauthorized.transcript.quorum_epoch =
        fixture->rosters[3].descriptor.epoch;
    unauthorized.transcript.quorum_base_hash =
        fixture->rosters[3].descriptor.base_hash;
    unauthorized.transcript.member_pro_tx_hash =
        fixture->rosters[3].members[0].pro_tx_hash;
    ShareCollectionError error{ShareCollectionError::NONE};
    BOOST_CHECK(collector->AddVerifiedShare(unauthorized, &error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(error == ShareCollectionError::INVALID_CONTEXT);

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        llmq_tests::ChainLockCollectorTestAccess::Insert(
            *collector, slot, QUORUM_THRESHOLD,
            static_cast<uint8_t>(0xa0 + slot));
    }
    const auto final{collector->Finalize()};
    BOOST_REQUIRE(final);
    BOOST_CHECK_EQUAL(final->selected_quorum_mask, 0b0111);
}

BOOST_AUTO_TEST_SUITE_END()
