// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_verify.h>

#include <support/cleanse.h>
#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
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

RosterBeaconWindow RecoveryWindow(uint32_t first_epoch)
{
    RosterBeaconWindow window;
    auto shared_anchor{ReadySeed(first_epoch)};
    shared_anchor.anchor_kind = RosterBeaconAnchorKind::RECOVERY;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto seed{shared_anchor};
        seed.epoch = first_epoch + static_cast<uint32_t>(slot);
        window.active.seeds[slot] = std::move(seed);
    }
    window.next.epoch = first_epoch + ACTIVE_QUORUMS;
    return window;
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
    transition.previous = authorization.previous;
    transition.new_window = statement.roster_beacons;
    const auto state_hash{
        GetRosterAuthorizationStateHash(genesis_hash, transition)};
    BOOST_REQUIRE(state_hash);
    statement.roster_authorization_state_hash = *state_hash;
}

void SetFirstMembers(QuorumBitmap& bitmap, std::size_t count)
{
    bitmap.fill(0);
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

ChildPublicKey UniqueChildKey(std::size_t quorum_slot, std::size_t member_index)
{
    ChildPublicKey key{};
    const uint64_t value{1 + quorum_slot * QUORUM_SIZE + member_index};
    key[0] = 0xc1;
    for (std::size_t byte{0}; byte < sizeof(value); ++byte) {
        key[1 + byte] = static_cast<uint8_t>(value >> (8 * byte));
    }
    return key;
}

struct VerificationFixture {
    uint256 genesis_hash{NonNullHash(9001)};
    ChainLockScheduleConfig schedule{.epoch_origin = 0};
    FinalChainLock chainlock;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    RosterAuthorizationVerificationContext authorization;
};

std::unique_ptr<VerificationFixture> MakeVerificationFixture()
{
    // A by-value return leaves fixture-sized temporaries in MSVC caller frames.
    auto fixture_storage = std::make_unique<VerificationFixture>();
    auto& fixture = *fixture_storage;
    fixture.chainlock.statement.height = 2000;
    fixture.chainlock.statement.block_hash = NonNullHash(9100);
    fixture.chainlock.statement.previous_chainlock_height = 1995;
    fixture.chainlock.statement.previous_chainlock_hash = NonNullHash(9099);
    fixture.chainlock.statement.quorum_context_hash = NonNullHash(1);
    fixture.chainlock.statement.payment_probation_state_hash = NonNullHash(2);
    fixture.chainlock.selected_quorum_mask = 0b0111;
    fixture.chainlock.signatures.resize(FINAL_SIGNATURE_COUNT);

    const auto active_epochs{ActiveEpochsAtHeight(
        fixture.schedule, fixture.chainlock.statement.height)};
    BOOST_REQUIRE(active_epochs);
    const uint32_t first_epoch{active_epochs->front().epoch};
    BOOST_REQUIRE(first_epoch > 0);

    RosterBeaconWindow previous_window;
    previous_window.active = ReadyBundle(first_epoch - 1);
    previous_window.next = ReadySeed(active_epochs->back().epoch);
    BOOST_REQUIRE(previous_window.IsStructurallyValid());
    fixture.authorization.predecessor_height =
        fixture.chainlock.statement.previous_chainlock_height;
    fixture.authorization.predecessor_block_hash =
        fixture.chainlock.statement.previous_chainlock_hash;
    fixture.authorization.previous = RosterAuthorizationPriorState{
        NonNullHash(9050), previous_window};
    fixture.chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::ROTATE;
    fixture.chainlock.statement.roster_beacons.active =
        ReadyBundle(first_epoch);
    fixture.chainlock.statement.roster_beacons.next.epoch =
        active_epochs->back().epoch + 1;
    BOOST_REQUIRE(
        fixture.chainlock.statement.roster_beacons.IsStructurallyValid());

    fixture.authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            fixture.chainlock.statement,
            *fixture.authorization.previous);

    SealRosterAuthorization(fixture.genesis_hash,
                            fixture.chainlock.statement,
                            fixture.authorization);

    for (std::size_t quorum_slot{0}; quorum_slot < ACTIVE_QUORUMS; ++quorum_slot) {
        auto& roster = fixture.rosters[quorum_slot];
        auto& descriptor = roster.descriptor;
        descriptor.epoch = (*active_epochs)[quorum_slot].epoch;
        descriptor.base_height = (*active_epochs)[quorum_slot].base_height;
        descriptor.base_hash = NonNullHash(9200 + quorum_slot);
        descriptor.snapshot_height = descriptor.base_height - 100;
        descriptor.snapshot_hash = NonNullHash(9300 + quorum_slot);
        const auto beacon_hash{GetRosterBeaconCommitmentHash(
            fixture.genesis_hash,
            fixture.chainlock.statement.roster_beacons.active
                .seeds[quorum_slot])};
        BOOST_REQUIRE(beacon_hash);
        descriptor.roster_beacon_hash = *beacon_hash;
        SetFirstMembers(descriptor.valid_members, QUORUM_MIN_VALID);
        descriptor.valid_count = QUORUM_MIN_VALID;

        for (std::size_t member_index{0}; member_index < QUORUM_SIZE; ++member_index) {
            auto& member = roster.members[member_index];
            member.pro_tx_hash = NonNullHash(1 + quorum_slot * 1000 + member_index);
            member.eligible = member_index < QUORUM_MIN_VALID;
            if (!member.eligible) continue;

            const auto authorization{
                test::MakeSyntheticChildAuthorization(
                    fixture.genesis_hash, member.pro_tx_hash,
                    descriptor.epoch,
                    UniqueChildKey(quorum_slot, member_index),
                    1 + quorum_slot * QUORUM_SIZE + member_index)};
            member.child_root = authorization.record;
        }
        descriptor.member_root = ComputeQuorumMemberRoot(fixture.genesis_hash, roster);
        descriptor.child_key_root = ComputeQuorumChildKeyRoot(fixture.genesis_hash, roster);

        if ((fixture.chainlock.selected_quorum_mask & (uint8_t{1} << quorum_slot)) != 0) {
            SetFirstMembers(fixture.chainlock.signer_bitmaps[quorum_slot], QUORUM_THRESHOLD);
        }
    }

    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture.rosters[slot].descriptor;
    }
    fixture.chainlock.statement.quorum_context_hash = GetQuorumContextHash(
        fixture.genesis_hash, fixture.chainlock.statement.height,
        fixture.chainlock.statement.block_hash, descriptors);
    std::size_t index{0};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((fixture.chainlock.selected_quorum_mask &
             (uint8_t{1} << slot)) == 0) {
            continue;
        }
        for (std::size_t member{0}; member < QUORUM_THRESHOLD;
             ++member, ++index) {
            const auto authorization{
                test::MakeSyntheticChildAuthorization(
                    fixture.genesis_hash,
                    fixture.rosters[slot].members[member].pro_tx_hash,
                    fixture.rosters[slot].descriptor.epoch,
                    UniqueChildKey(slot, member),
                    1 + slot * QUORUM_SIZE + member)};
            fixture.chainlock.signatures[index].key_proof =
                authorization.proof;
            fixture.chainlock.signatures[index].signature[0] =
                static_cast<uint8_t>(index);
            fixture.chainlock.signatures[index].signature[1] =
                static_cast<uint8_t>(index >> 8);
        }
    }
    return fixture_storage;
}

void ClearMember(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] &=
        static_cast<uint8_t>(~static_cast<uint8_t>(uint8_t{1} << (member % 8)));
}

void SetMember(QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(roster_context_memory_counter_tracks_capability_lifetime)
{
    const auto fixture{MakeVerificationFixture()};
    const std::size_t baseline{
        GetPQVerificationMemoryStats().live_roster_contexts};
    auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters))};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK_EQUAL(
        GetPQVerificationMemoryStats().live_roster_contexts,
        baseline + 1);
    roster_set.reset();
    BOOST_CHECK_EQUAL(
        GetPQVerificationMemoryStats().live_roster_contexts, baseline);
}

BOOST_AUTO_TEST_CASE(preparation_recomputes_roots_context_and_canonical_mapping)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::INVALID_ARGUMENT};
    auto prepared = PrepareFinalChainLockVerification(
        fixture->genesis_hash, fixture->schedule, fixture->chainlock,
        fixture->rosters,
        fixture->authorization, &error);
    BOOST_REQUIRE(prepared.has_value());
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_REQUIRE_EQUAL(prepared->checks.size(), FINAL_SIGNATURE_COUNT);

    // The serialized signature order crosses from the last threshold member
    // quorum slot 1/member 0 without an encoded index.
    const auto signature_tag = [](const ScheduledWOTSCheck& check) {
        return static_cast<uint16_t>(check.GetSignature()[0]) |
               (static_cast<uint16_t>(check.GetSignature()[1]) << 8);
    };
    BOOST_CHECK_EQUAL(signature_tag(prepared->checks[0]), 0U);
    BOOST_CHECK_EQUAL(
        signature_tag(prepared->checks[QUORUM_THRESHOLD - 1]),
        QUORUM_THRESHOLD - 1);
    BOOST_CHECK_EQUAL(
        signature_tag(prepared->checks[QUORUM_THRESHOLD]),
        QUORUM_THRESHOLD);

    const auto& member = fixture->rosters[1].members[0];
    const auto transcript = BuildChainLockShareTranscript(
        fixture->chainlock, fixture->rosters[1].descriptor, 0, member.pro_tx_hash);
    const uint256 expected_hash = GetChainLockShareHash(fixture->genesis_hash, transcript);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        prepared->checks[QUORUM_THRESHOLD].GetMessageBytes().begin(),
        prepared->checks[QUORUM_THRESHOLD].GetMessageBytes().end(), expected_hash.begin(),
        expected_hash.end());
    BOOST_CHECK(prepared->checks[QUORUM_THRESHOLD].GetPublicKey() ==
                UniqueChildKey(1, 0));
    const auto expected_leaf{ChainLockLeafIndex(
        fixture->schedule, fixture->rosters[1].descriptor.epoch,
        fixture->chainlock.statement.height)};
    BOOST_REQUIRE(expected_leaf);
    BOOST_CHECK_EQUAL(
        prepared->checks[QUORUM_THRESHOLD].GetLeafIndex(), *expected_leaf);
}

BOOST_AUTO_TEST_CASE(verified_roster_preparation_reuses_intrinsic_validation)
{
    const auto fixture{MakeVerificationFixture()};
    const auto rosters{
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters)};
    ChainLockVerificationError error{
        ChainLockVerificationError::INVALID_ARGUMENT};
    const uint64_t capability_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash, rosters, &error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting() -
                          capability_hashes_before,
                      8'184U);

    const uint64_t prepared_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    auto prepared{PrepareFinalChainLockVerification(
        fixture->schedule, fixture->chainlock, *roster_set,
        fixture->authorization, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      prepared_hashes_before);

    auto raw{PrepareFinalChainLockVerification(
        fixture->genesis_hash, fixture->schedule, fixture->chainlock,
        fixture->rosters, fixture->authorization, &error)};
    BOOST_REQUIRE(raw);
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

    auto bad_context{fixture->chainlock};
    bad_context.statement.quorum_context_hash.begin()[0] ^= 1;
    const uint64_t rejection_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        fixture->schedule, bad_context, *roster_set,
        fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);

    auto bad_selection{fixture->chainlock};
    bad_selection.selected_quorum_mask = 0b1011;
    bad_selection.signer_bitmaps[3] = bad_selection.signer_bitmaps[2];
    bad_selection.signer_bitmaps[2].fill(0);
    BOOST_REQUIRE(bad_selection.IsStructurallyValid());
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        fixture->schedule, bad_selection, *roster_set,
        fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto bad_proof{fixture->chainlock};
    bad_proof.signatures[0].key_proof.siblings[0].begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        fixture->schedule, bad_proof, *roster_set,
        fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      rejection_hashes_before);

    auto underfilled{MakeVerificationFixture()};
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
    underfilled->chainlock.statement.quorum_context_hash =
        GetQuorumContextHash(
            underfilled->genesis_hash,
            underfilled->chainlock.statement.height,
            underfilled->chainlock.statement.block_hash, descriptors);
    const auto underfilled_rosters{
        std::make_shared<const FrozenQuorumRosters>(underfilled->rosters)};
    const auto underfilled_set{VerifiedRosterSet::Create(
        underfilled->genesis_hash, underfilled_rosters, &error)};
    BOOST_REQUIRE(underfilled_set);
    const uint64_t underfilled_hashes_before{
        GetQuorumRootTaggedHashCountForTesting()};
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        underfilled->schedule, underfilled->chainlock,
        *underfilled_set, underfilled->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_DESCRIPTOR);
    BOOST_CHECK_EQUAL(GetQuorumRootTaggedHashCountForTesting(),
                      underfilled_hashes_before);
}

BOOST_AUTO_TEST_CASE(preparation_rejects_root_context_index_and_bitmap_corruption)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};

    {
        auto bad_member_root = MakeVerificationFixture();
        bad_member_root->rosters[0].descriptor.member_root.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_member_root->genesis_hash, bad_member_root->schedule,
            bad_member_root->chainlock,
            bad_member_root->rosters, bad_member_root->authorization,
            &error));
        BOOST_CHECK(error == ChainLockVerificationError::MEMBER_ROOT_MISMATCH);
    }

    {
        auto bad_child_root = MakeVerificationFixture();
        bad_child_root->rosters[0].descriptor.child_key_root.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_child_root->genesis_hash, bad_child_root->schedule,
            bad_child_root->chainlock,
            bad_child_root->rosters, bad_child_root->authorization,
            &error));
        BOOST_CHECK(error == ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);
    }

    {
        auto bad_context = MakeVerificationFixture();
        bad_context->chainlock.statement.quorum_context_hash.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_context->genesis_hash, bad_context->schedule,
            bad_context->chainlock,
            bad_context->rosters, bad_context->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
    }

    {
        auto bad_index = MakeVerificationFixture();
        ClearMember(bad_index->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        SetMember(bad_index->chainlock.signer_bitmaps[0], QUORUM_MIN_VALID);
        BOOST_REQUIRE(bad_index->chainlock.IsStructurallyValid());
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_index->genesis_hash, bad_index->schedule,
            bad_index->chainlock, bad_index->rosters,
            bad_index->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::INVALID_SIGNER);
    }

    {
        auto bad_bitmap = MakeVerificationFixture();
        ClearMember(bad_bitmap->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_bitmap->genesis_hash, bad_bitmap->schedule,
            bad_bitmap->chainlock,
            bad_bitmap->rosters, bad_bitmap->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHAINLOCK);
    }
}

BOOST_AUTO_TEST_CASE(preparation_rejects_mutated_child_membership_witness)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto bad_sibling = MakeVerificationFixture();
    bad_sibling->chainlock.signatures[0].key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        bad_sibling->genesis_hash, bad_sibling->schedule,
        bad_sibling->chainlock,
        bad_sibling->rosters, bad_sibling->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);

    auto bad_public_key = MakeVerificationFixture();
    bad_public_key->chainlock.signatures[0].key_proof.public_key[0] ^= 1;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        bad_public_key->genesis_hash, bad_public_key->schedule,
        bad_public_key->chainlock,
        bad_public_key->rosters, bad_public_key->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);
}

BOOST_AUTO_TEST_CASE(preparation_rejects_duplicate_members_and_child_keys)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto duplicate_member = MakeVerificationFixture();
    duplicate_member->rosters[0].members.back().pro_tx_hash =
        duplicate_member->rosters[0].members[QUORUM_SIZE - 2].pro_tx_hash;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        duplicate_member->genesis_hash, duplicate_member->schedule,
        duplicate_member->chainlock,
        duplicate_member->rosters, duplicate_member->authorization,
        &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_MEMBER);

    auto duplicate_key = MakeVerificationFixture();
    duplicate_key->rosters[0].members[1]
        .child_root->commitment.tree_id =
        duplicate_key->rosters[0].members[0]
            .child_root->commitment.tree_id;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        duplicate_key->genesis_hash, duplicate_key->schedule,
        duplicate_key->chainlock,
        duplicate_key->rosters, duplicate_key->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_CHILD_KEY);
}

BOOST_AUTO_TEST_CASE(real_signature_check_and_owned_queue_lifecycle)
{
    BOOST_CHECK_EQUAL(
        GetPQVerificationMemoryStats().verification_worker_pinned_bytes,
        0U);
    scheduled_wots::KeyGenerationSeed seed{};
    scheduled_wots::Message message;
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = i;
    for (std::size_t i{0}; i < message.size(); ++i) message[i] = (3 + 7 * i) & 0xff;

    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));
    constexpr uint8_t LEAF_INDEX{17};
    scheduled_wots::Signature signature;
    BOOST_REQUIRE(scheduled_wots::SignDeterministic(
        *secret_key, LEAF_INDEX, message, signature));

    {
        ChainLockVerifier verifier{/*worker_threads=*/2, /*batch_size=*/1};
        std::vector<ScheduledWOTSCheck> checks;
        checks.emplace_back(public_key, LEAF_INDEX, message, signature);
        checks.emplace_back(public_key, LEAF_INDEX, message, signature);
        BOOST_CHECK(verifier.VerifyChecks(std::move(checks)));

        auto bad_signature = signature;
        bad_signature[0] ^= 1;
        std::vector<ScheduledWOTSCheck> bad_checks;
        bad_checks.emplace_back(
            public_key, LEAF_INDEX, message, std::move(bad_signature));
        BOOST_CHECK(!verifier.VerifyChecks(std::move(bad_checks)));

        std::vector<ScheduledWOTSCheck> wrong_leaf_checks;
        wrong_leaf_checks.emplace_back(
            public_key, static_cast<uint8_t>(LEAF_INDEX + 1), message,
            signature);
        BOOST_CHECK(!verifier.VerifyChecks(std::move(wrong_leaf_checks)));
        BOOST_CHECK_EQUAL(
            GetPQVerificationMemoryStats()
                .verification_worker_pinned_bytes,
            0U);
    }

    // A zero-worker queue is a supported lifecycle: the calling thread owns
    // all work, and an empty batch is a successful no-op for helper users.
    {
        ChainLockVerifier verifier{/*worker_threads=*/0};
        std::vector<ScheduledWOTSCheck> checks;
        checks.emplace_back(public_key, LEAF_INDEX, message, signature);
        BOOST_CHECK(verifier.VerifyChecks(std::move(checks)));
        BOOST_CHECK(verifier.VerifyChecks({}));
        BOOST_CHECK_EQUAL(
            GetPQVerificationMemoryStats()
                .verification_worker_pinned_bytes,
            0U);
    }

    BOOST_CHECK_THROW(
        ChainLockVerifier(static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1),
        std::invalid_argument);
    memory_cleanse(seed.data(), seed.size());
}

BOOST_AUTO_TEST_CASE(authorization_is_derived_from_authenticated_transition)
{
    auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto rotation_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        fixture->authorization, &error)};
    BOOST_REQUIRE(rotation_mask);
    BOOST_CHECK_EQUAL(*rotation_mask, 0b0111);
    BOOST_CHECK(PrepareFinalChainLockVerification(
        fixture->genesis_hash, fixture->schedule, fixture->chainlock,
        fixture->rosters, fixture->authorization, &error));

    // A syntactically correct state-hash edge is not sufficient for LIVE:
    // the verifier must receive and recheck the exact external policy facts.
    auto missing_normal_policy{fixture->authorization};
    missing_normal_policy.normal_input.reset();
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        missing_normal_policy, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto inactive_rotation{fixture->authorization};
    BOOST_REQUIRE(inactive_rotation.normal_input);
    BOOST_REQUIRE(inactive_rotation.normal_input->ready_rotation);
    inactive_rotation.normal_input->ready_rotation->is_active = false;
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        inactive_rotation, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto missing_predecessor{fixture->authorization};
    missing_predecessor.previous.reset();
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        missing_predecessor, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto wrong_predecessor{fixture->authorization};
    wrong_predecessor.predecessor_block_hash.begin()[0] ^= 1;
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        wrong_predecessor, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto tampered_state{fixture->chainlock.statement};
    tampered_state.roster_authorization_state_hash.begin()[0] ^= 1;
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, tampered_state, fixture->authorization,
        &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto keep_statement{fixture->chainlock.statement};
    keep_statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    RosterAuthorizationVerificationContext keep_authorization;
    keep_authorization.predecessor_height =
        keep_statement.previous_chainlock_height;
    keep_authorization.predecessor_block_hash =
        keep_statement.previous_chainlock_hash;
    keep_authorization.previous = RosterAuthorizationPriorState{
        NonNullHash(9060), keep_statement.roster_beacons};
    keep_authorization.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            keep_statement, *keep_authorization.previous);
    SealRosterAuthorization(fixture->genesis_hash, keep_statement,
                            keep_authorization);
    const auto keep_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, keep_statement, keep_authorization,
        &error)};
    BOOST_REQUIRE(keep_mask);
    BOOST_CHECK_EQUAL(*keep_mask, 0b1111);

    auto attested_history{keep_authorization};
    attested_history.admission =
        RosterAuthorizationAdmission::ATTESTED_HISTORY;
    attested_history.previous.reset();
    attested_history.normal_input.reset();
    const auto attested_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, keep_statement, attested_history, &error)};
    BOOST_REQUIRE(attested_mask);
    BOOST_CHECK_EQUAL(*attested_mask, 0b1111);

    fixture->chainlock.selected_quorum_mask = 0b1011;
    fixture->chainlock.signer_bitmaps[3] =
        fixture->chainlock.signer_bitmaps[2];
    fixture->chainlock.signer_bitmaps[2].fill(0);
    BOOST_REQUIRE(fixture->chainlock.IsStructurallyValid());
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        fixture->genesis_hash, fixture->schedule, fixture->chainlock,
        fixture->rosters, fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
}

BOOST_AUTO_TEST_CASE(initialization_and_recovery_require_explicit_admission)
{
    auto fixture{MakeVerificationFixture()};
    auto statement{fixture->chainlock.statement};
    statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    statement.roster_beacons = RecoveryWindow(/*first_epoch=*/0);

    RosterAuthorizationVerificationContext initialize;
    initialize.admission = RosterAuthorizationAdmission::INITIALIZE;
    initialize.predecessor_height = statement.previous_chainlock_height;
    initialize.predecessor_block_hash = statement.previous_chainlock_hash;
    SealRosterAuthorization(fixture->genesis_hash, statement, initialize);
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto initialize_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, initialize, &error)};
    BOOST_REQUIRE(initialize_mask);
    BOOST_CHECK_EQUAL(*initialize_mask, 0b1111);

    auto ordinary_live{initialize};
    ordinary_live.admission = RosterAuthorizationAdmission::LIVE;
    ordinary_live.previous = fixture->authorization.previous;
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, ordinary_live, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    auto recover{initialize};
    recover.admission = RosterAuthorizationAdmission::RECOVER;
    SealRosterAuthorization(fixture->genesis_hash, statement, recover);
    const auto recovery_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, recover, &error)};
    BOOST_REQUIRE(recovery_mask);
    BOOST_CHECK_EQUAL(*recovery_mask, 0b1111);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, ordinary_live, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
}

BOOST_AUTO_TEST_CASE(descriptors_bind_the_exact_active_beacon_seed)
{
    auto fixture{MakeVerificationFixture()};
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    fixture->rosters[1].descriptor.roster_beacon_hash.begin()[0] ^= 1;
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    fixture->chainlock.statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, fixture->chainlock.statement.height,
        fixture->chainlock.statement.block_hash, descriptors);
    BOOST_CHECK(!ValidateFrozenQuorumContext(
        fixture->genesis_hash, fixture->chainlock.statement,
        fixture->rosters, fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER_BEACON);
}

BOOST_AUTO_TEST_CASE(full_verifier_reports_bad_signature_after_cheap_checks)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    BOOST_CHECK(!VerifyFinalChainLock(
        fixture->genesis_hash, fixture->schedule, fixture->chainlock,
        fixture->rosters, fixture->authorization,
        /*queue=*/nullptr, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_SIGNATURE);
}

BOOST_AUTO_TEST_SUITE_END()
