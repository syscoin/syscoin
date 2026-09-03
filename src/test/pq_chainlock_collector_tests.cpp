// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_collector.h>

#include <streams.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

static_assert(!std::is_default_constructible_v<
              CollectedChainLockFinalization>);
static_assert(!std::is_copy_constructible_v<
              CollectedChainLockFinalization>);
static_assert(!std::is_constructible_v<
              CollectedChainLockFinalization,
              FinalChainLock,
              PreparedChainLockContextPtr>);
static_assert(std::is_same_v<
              decltype(std::declval<const CollectedChainLockFinalization&>()
                           .Certificate()),
              const FinalChainLock&>);

namespace llmq_tests {

class ChainLockCollectorTestAccess {
public:
    static void InsertFrom(ChainLockCollector& collector,
                           std::size_t quorum_slot,
                           std::size_t first_member,
                           std::size_t count,
                           uint8_t tag)
    {
        for (std::size_t member{first_member};
             member < first_member + count; ++member) {
            AuthenticatedChildSignature signature;
            signature.key_proof.public_key[0] = 1;
            signature.signature[0] = tag;
            signature.signature[1] = static_cast<uint8_t>(member);
            signature.signature[2] = static_cast<uint8_t>(member >> 8);
            collector.m_shares[quorum_slot].emplace(
                static_cast<uint16_t>(member), std::move(signature));
        }
    }

    static void Insert(ChainLockCollector& collector,
                       std::size_t quorum_slot,
                       std::size_t count,
                       uint8_t tag)
    {
        InsertFrom(collector, quorum_slot, 0, count, tag);
    }
};

} // namespace llmq_tests

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

RosterBeaconSeed ReadySeed(uint32_t epoch)
{
    RosterBeaconSeed seed;
    seed.state = RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = BTCCursor{
        10'000 + static_cast<int32_t>(epoch),
        NonNullHash(100'000 + epoch), NonNullHash(200'000 + epoch)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(300'000 + epoch);
    return seed;
}

ActiveRosterBeaconBundle ReadyBundle(uint32_t first_epoch)
{
    ActiveRosterBeaconBundle bundle;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        bundle.seeds[slot] =
            ReadySeed(first_epoch + static_cast<uint32_t>(slot));
    }
    return bundle;
}

void BindRecoverySource(ActiveRosterBeaconBundle& bundle)
{
    bundle.recovery_authority_source.normal_beacon =
        bundle.seeds.back();
}

void SealRosterAuthorization(
    const uint256& genesis_hash,
    ChainLockStatement& statement,
    const RosterAuthorizationVerificationContext& authorization)
{
    RosterAuthorizationTransition transition;
    transition.kind = statement.roster_transition;
    transition.target_height = statement.height;
    transition.target_block_hash = statement.block_hash;
    transition.predecessor_height = statement.previous_chainlock_height;
    transition.predecessor_block_hash = statement.previous_chainlock_hash;
    transition.authorization_base = statement.roster_authorization_base;
    transition.previous = authorization.previous;
    transition.new_window = statement.roster_beacons;
    const auto state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    BOOST_REQUIRE(state_hash);
    statement.roster_authorization_state_hash = *state_hash;
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
    RosterAuthorizationVerificationContext authorization;
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
    const uint32_t first_epoch{active_epochs->front().epoch};
    fixture->statement.roster_beacons.active = ReadyBundle(first_epoch);
    BindRecoverySource(fixture->statement.roster_beacons.active);
    fixture->statement.roster_beacons.next.epoch =
        active_epochs->back().epoch + 1;
    RosterBeaconWindow previous_window{fixture->statement.roster_beacons};
    fixture->authorization.predecessor_height =
        fixture->statement.previous_chainlock_height;
    fixture->authorization.predecessor_block_hash =
        fixture->statement.previous_chainlock_hash;
    fixture->authorization.reset_policy = RosterResetVerificationPolicy{
        fixture->schedule, BTCCScheduleConfig{.candidate_origin = 865},
        864};
    fixture->statement.roster_authorization_base = {
        fixture->statement.previous_chainlock_height,
        fixture->statement.previous_chainlock_hash,
        NonNullHash(7096)};
    fixture->authorization.authorization_base =
        fixture->statement.roster_authorization_base;
    fixture->authorization.previous = RosterAuthorizationPriorState{
        NonNullHash(7097), previous_window};
    fixture->statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    fixture->authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            fixture->statement, *fixture->authorization.previous);
    SealRosterAuthorization(
        fixture->genesis_hash, fixture->statement, fixture->authorization);

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = (*active_epochs)[slot].epoch;
        descriptor.base_height = (*active_epochs)[slot].base_height;
        descriptor.base_hash = NonNullHash(7200 + slot);
        descriptor.snapshot_height = descriptor.base_height - 144;
        descriptor.snapshot_hash = NonNullHash(7300 + slot);
        descriptor.roster_beacon_hash = *GetRosterBeaconCommitmentHash(
            fixture->genesis_hash,
            fixture->statement.roster_beacons.active.seeds[slot]);

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
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto roster_set{VerifiedRosterSet::Create(
        fixture.genesis_hash, ShareRosters(fixture), &error)};
    BOOST_REQUIRE(roster_set);
    return PreparedChainLockContext::Create(
        fixture.schedule, fixture.statement, std::move(roster_set),
        fixture.authorization, &error);
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
    const uint64_t root_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, rosters, &verification_error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(verification_error == ChainLockVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          root_hashes_before,
                      8'184U);
    BOOST_CHECK(roster_set->RostersPtr() != rosters);
    const uint64_t prepared_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto context{PreparedChainLockContext::Create(
        fixture->schedule, fixture->statement, roster_set,
        fixture->authorization, &verification_error)};
    BOOST_REQUIRE(context);
    BOOST_CHECK(verification_error == ChainLockVerificationError::NONE);
    BOOST_CHECK(context->RosterSetPtr() == roster_set);
    BOOST_CHECK(context->RostersPtr() == roster_set->RostersPtr());
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_hashes_before);

    const ChainLockShare share{SignFirstShare(*fixture)};
    const uint64_t prepared_share_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto prepared_check{PrepareChainLockShareVerification(
        share, *context, &verification_error)};
    BOOST_REQUIRE(prepared_check);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_share_hashes_before);
    BOOST_CHECK((*prepared_check)());

    const auto expect_rejection{
        [&](const ChainLockShare& candidate,
            const PreparedChainLockContext& prepared,
            ChainLockVerificationError expected) {
            ChainLockVerificationError prepared_error{
                ChainLockVerificationError::NONE};
            BOOST_CHECK(!PrepareChainLockShareVerification(
                candidate, prepared, &prepared_error));
            BOOST_CHECK(prepared_error == expected);
        }};

    auto unknown_quorum{share};
    unknown_quorum.transcript.quorum_base_hash = NonNullHash(7995);
    expect_rejection(
        unknown_quorum, *context,
        ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto bad_proof{share};
    bad_proof.authenticated_signature.key_proof.siblings[0].begin()[0] ^= 1;
    expect_rejection(
        bad_proof, *context,
        ChainLockVerificationError::INVALID_CHILD_PROOF);

    auto invalid_authorization{fixture->authorization};
    invalid_authorization.admission =
        RosterAuthorizationAdmission::INITIALIZE;
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, fixture->statement, roster_set,
        invalid_authorization, &verification_error));
    BOOST_CHECK(verification_error ==
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
    auto alternate_authorization{fixture->authorization};
    alternate_authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            alternate_statement, *alternate_authorization.previous);
    SealRosterAuthorization(
        fixture->genesis_hash, alternate_statement,
        alternate_authorization);
    const auto original_statement{fixture->statement};
    fixture->statement = alternate_statement;
    const ChainLockShare alternate_share{SignFirstShare(*fixture)};
    fixture->statement = original_statement;
    const uint64_t alternate_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto alternate_context{PreparedChainLockContext::Create(
        fixture->schedule, alternate_statement, roster_set,
        alternate_authorization,
        &verification_error)};
    BOOST_REQUIRE(alternate_context);
    BOOST_CHECK(alternate_context->RosterSetPtr() == roster_set);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      alternate_hashes_before);

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
    BOOST_CHECK(exact_collector->GetPreparedContext() == context);
    BOOST_CHECK(exact_collector->AddVerifiedShare(
                    alternate_share, &alternate_collection_error) ==
                ShareCollectionResult::REJECTED);
    BOOST_CHECK(alternate_collection_error ==
                ShareCollectionError::STATEMENT_MISMATCH);
    alternate_context.reset();

    auto mutable_rosters{std::make_shared<FrozenQuorumRosters>(*rosters)};
    FrozenQuorumRostersPtr aliased_rosters{mutable_rosters};
    auto alias_safe_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, aliased_rosters, &verification_error)};
    BOOST_REQUIRE(alias_safe_set);
    auto alias_safe_context{PreparedChainLockContext::Create(
        fixture->schedule, fixture->statement, alias_safe_set,
        fixture->authorization, &verification_error)};
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
    BOOST_CHECK(!VerifiedRosterSet::Create(
        fixture->genesis_hash, bad_rosters, &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::MEMBER_ROOT_MISMATCH);

    auto bad_statement{fixture->statement};
    bad_statement.quorum_context_hash.begin()[0] ^= 1;
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, std::move(bad_statement), roster_set,
        fixture->authorization,
        &verification_error));
    BOOST_CHECK(verification_error ==
                ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);

    std::weak_ptr<const PreparedChainLockContext> retained{context};
    auto collector{ChainLockCollector::Create(context)};
    BOOST_REQUIRE(collector);
    BOOST_CHECK(collector->GetPreparedContext() == context);
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
        PrepareContext(*fixture), &error)};
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

BOOST_AUTO_TEST_CASE(compact_share_round_trip_binds_exact_context_and_position)
{
    const auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    const auto context{PrepareContext(*fixture)};
    BOOST_REQUIRE(context);
    const ChainLockShare share{SignFirstShare(*fixture)};

    const auto first{PackChainLockShareSignerPosition(0, 0)};
    const auto end_first{PackChainLockShareSignerPosition(0, 399)};
    const auto start_second{PackChainLockShareSignerPosition(1, 0)};
    const auto last{PackChainLockShareSignerPosition(3, 399)};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(end_first);
    BOOST_REQUIRE(start_second);
    BOOST_REQUIRE(last);
    BOOST_CHECK_EQUAL(*first, 0U);
    BOOST_CHECK_EQUAL(*end_first, 399U);
    BOOST_CHECK_EQUAL(*start_second, 400U);
    BOOST_CHECK_EQUAL(*last, 1'599U);
    BOOST_CHECK(!PackChainLockShareSignerPosition(4, 0));
    BOOST_CHECK(!PackChainLockShareSignerPosition(0, 400));

    const auto compact{BuildCompactChainLockShare(share, *context)};
    BOOST_REQUIRE(compact);
    BOOST_CHECK(!compact->statement_logical_id.IsNull());
    BOOST_CHECK(compact->statement_logical_id ==
                context->StatementLogicalId());
    BOOST_CHECK_EQUAL(compact->signer_position, 0U);
    DataStream encoded;
    encoded << *compact;
    BOOST_CHECK_EQUAL(encoded.size(), CompactChainLockShare::WIRE_SIZE);

    CompactChainLockShare decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK(decoded == *compact);
    const auto expanded{ExpandCompactChainLockShare(decoded, *context)};
    BOOST_REQUIRE(expanded);
    BOOST_CHECK(*expanded == share);

    auto distinct_statement{fixture->statement};
    distinct_statement.payment_probation_state_hash.begin()[0] ^= 1;
    BOOST_CHECK(distinct_statement.quorum_context_hash ==
                fixture->statement.quorum_context_hash);
    BOOST_CHECK(GetLogicalChainLockId(
                    fixture->genesis_hash, distinct_statement) !=
                context->StatementLogicalId());
    auto wrong_context{decoded};
    wrong_context.statement_logical_id = GetLogicalChainLockId(
        fixture->genesis_hash, distinct_statement);
    BOOST_CHECK(!ExpandCompactChainLockShare(wrong_context, *context));

    auto moved_signer{decoded};
    moved_signer.signer_position =
        *PackChainLockShareSignerPosition(0, 1);
    const auto moved_share{
        ExpandCompactChainLockShare(moved_signer, *context)};
    BOOST_REQUIRE(moved_share);
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    BOOST_CHECK(!PrepareChainLockShareVerification(
        *moved_share, *context, &error));
    BOOST_CHECK(error != ChainLockVerificationError::NONE);

    auto invalid_position{decoded};
    invalid_position.signer_position =
        static_cast<uint16_t>(ACTIVE_QUORUMS * QUORUM_SIZE);
    BOOST_CHECK(!invalid_position.IsStructurallyValid());
    DataStream invalid_encoded;
    invalid_encoded << invalid_position;
    CompactChainLockShare invalid_decoded;
    BOOST_CHECK_THROW(invalid_encoded >> invalid_decoded,
                      std::ios_base::failure);

    auto null_context{decoded};
    null_context.statement_logical_id.SetNull();
    BOOST_CHECK(!null_context.IsStructurallyValid());
    DataStream null_encoded;
    null_encoded << null_context;
    CompactChainLockShare null_decoded;
    BOOST_CHECK_THROW(null_encoded >> null_decoded,
                      std::ios_base::failure);
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
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
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
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
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
    auto prepared_context{PrepareContext(*fixture)};
    BOOST_REQUIRE(prepared_context);
    std::weak_ptr<const PreparedChainLockContext> retained_context{
        prepared_context};
    auto collector{ChainLockCollector::Create(prepared_context)};
    BOOST_REQUIRE(collector);
    prepared_context.reset();

    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 0, QUORUM_THRESHOLD - 1, 0xa0);
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 1, QUORUM_THRESHOLD, 0xb1);
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 2, QUORUM_THRESHOLD, 0xc2);
    BOOST_CHECK(!collector->IsComplete());
    BOOST_CHECK(!collector->FinalizeCollection());
    llmq_tests::ChainLockCollectorTestAccess::Insert(
        *collector, 3, QUORUM_THRESHOLD, 0xd3);
    BOOST_CHECK(collector->IsComplete());

    const auto collected{collector->FinalizeCollection()};
    BOOST_REQUIRE(collected);
    const auto* final{&collected->Certificate()};
    BOOST_CHECK(collected->ContextPtr() == retained_context.lock());
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

    auto detached_copy{*final};
    detached_copy.statement.block_hash = NonNullHash(7994);
    BOOST_CHECK(collected->Certificate().statement.block_hash !=
                detached_copy.statement.block_hash);
    collector.reset();
    BOOST_CHECK(!retained_context.expired());
    BOOST_CHECK(collected->ContextPtr() == retained_context.lock());
}

BOOST_AUTO_TEST_CASE(finalization_is_immutable_while_late_shares_remain_accepted)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
    BOOST_REQUIRE(collector);

    const ChainLockShare late_lower_quorum_share{SignFirstShare(*fixture)};
    ShareCollectionError error{ShareCollectionError::INVALID_ARGUMENT};
    auto pending{collector->ReserveShareVerification(
        late_lower_quorum_share, &error)};
    BOOST_REQUIRE(pending);
    BOOST_CHECK(error == ShareCollectionError::NONE);

    // Leave member zero pending so this lower quorum reaches threshold only
    // after the first exact certificate has been frozen.
    llmq_tests::ChainLockCollectorTestAccess::InsertFrom(
        *collector, 0, 1, QUORUM_THRESHOLD - 1, 0xa0);
    for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
        llmq_tests::ChainLockCollectorTestAccess::Insert(
            *collector, slot, QUORUM_THRESHOLD,
            static_cast<uint8_t>(0xa0 + slot));
    }

    const auto first{collector->FinalizeCollection()};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE_EQUAL(first->Certificate().selected_quorum_mask, 0b1110);
    const uint256 first_witness{
        first->Certificate().GetWitnessId(fixture->genesis_hash)};
    DataStream first_bytes;
    first_bytes << first->Certificate();
    BOOST_REQUIRE_EQUAL(first_bytes.size(), FinalChainLock::WIRE_SIZE);

    ChainLockCollector::VerifyReservedShare(*pending);
    BOOST_CHECK(collector->CompleteShareVerification(
                    std::move(*pending), &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], QUORUM_THRESHOLD);

    // The exact accepted slot is still permanently deduplicated after the
    // certificate snapshot, without closing collection to other late members.
    BOOST_CHECK(collector->AddVerifiedShare(
                    late_lower_quorum_share, &error) ==
                ShareCollectionResult::DUPLICATE);
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], QUORUM_THRESHOLD);

    const auto second{collector->FinalizeCollection()};
    BOOST_REQUIRE(second);
    BOOST_CHECK(first == second);
    BOOST_CHECK_EQUAL(second->Certificate().selected_quorum_mask, 0b1110);
    BOOST_CHECK(second->Certificate().GetWitnessId(fixture->genesis_hash) ==
                first_witness);
    DataStream second_bytes;
    second_bytes << second->Certificate();
    BOOST_REQUIRE_EQUAL(second_bytes.size(), first_bytes.size());
    BOOST_CHECK(std::equal(first_bytes.begin(), first_bytes.end(),
                           second_bytes.begin()));
}

BOOST_AUTO_TEST_CASE(finalization_does_not_close_new_share_reservations)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
    BOOST_REQUIRE(collector);

    for (std::size_t slot{1}; slot < ACTIVE_QUORUMS; ++slot) {
        llmq_tests::ChainLockCollectorTestAccess::Insert(
            *collector, slot, QUORUM_THRESHOLD,
            static_cast<uint8_t>(0xa0 + slot));
    }
    const auto finalized{collector->FinalizeCollection()};
    BOOST_REQUIRE(finalized);

    const ChainLockShare late_share{SignFirstShare(*fixture)};
    ShareCollectionError error{ShareCollectionError::INVALID_ARGUMENT};
    BOOST_CHECK(collector->AddVerifiedShare(late_share, &error) ==
                ShareCollectionResult::ACCEPTED);
    BOOST_CHECK(error == ShareCollectionError::NONE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
    BOOST_CHECK(collector->FinalizeCollection() == finalized);

    BOOST_CHECK(collector->AddVerifiedShare(late_share, &error) ==
                ShareCollectionResult::DUPLICATE);
    BOOST_CHECK(error == ShareCollectionError::DUPLICATE);
    BOOST_CHECK_EQUAL(collector->ShareCounts()[0], 1U);
}

BOOST_AUTO_TEST_CASE(one_transition_ignores_and_rejects_newest_roster)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    const uint32_t first_epoch{
        fixture->statement.roster_beacons.active.seeds.front().epoch};
    RosterBeaconWindow previous_window;
    previous_window.active = ReadyBundle(first_epoch - 1);
    previous_window.next = ReadySeed(first_epoch + ACTIVE_QUORUMS - 1);
    previous_window.active.recovery_authority_source =
        fixture->statement.roster_beacons.active.recovery_authority_source;
    fixture->authorization.previous = RosterAuthorizationPriorState{
        NonNullHash(7096), previous_window};
    fixture->statement.roster_transition =
        RosterAuthorizationTransitionKind::ROTATE;
    fixture->authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            fixture->statement, *fixture->authorization.previous);
    SealRosterAuthorization(fixture->genesis_hash, fixture->statement,
                            fixture->authorization);
    auto collector{ChainLockCollector::Create(PrepareContext(*fixture))};
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
    const auto finalized{collector->FinalizeCollection()};
    BOOST_REQUIRE(finalized);
    const auto* final{&finalized->Certificate()};
    BOOST_CHECK_EQUAL(final->selected_quorum_mask, 0b0111);
}

BOOST_AUTO_TEST_SUITE_END()
