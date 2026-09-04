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
#include <future>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
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
    bundle.recovery_authority_source.normal_beacon = bundle.seeds.back();
    return bundle;
}

RosterBeaconWindow RecoveryWindow(
    uint32_t first_epoch,
    const ActiveRosterBeaconBundle& durable_authority)
{
    const auto window{MakeRecoveryRosterBeaconWindow(
        durable_authority.recovery_authority_source,
        first_epoch + static_cast<uint32_t>(ACTIVE_QUORUMS - 1))};
    BOOST_REQUIRE(window);
    return *window;
}

RosterResetVerificationPolicy ResetPolicy(
    const ChainLockScheduleConfig& schedule)
{
    return RosterResetVerificationPolicy{
        schedule, BTCCScheduleConfig{.candidate_origin = 865}, 864};
}

RosterBeaconWindow InitializationWindow(uint32_t first_epoch)
{
    RosterBeaconWindow window;
    const auto shared{ReadySeed(first_epoch)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto seed{shared};
        seed.epoch = first_epoch + static_cast<uint32_t>(slot);
        window.active.seeds[slot] = std::move(seed);
    }
    window.active.recovery_authority_source.normal_beacon =
        window.active.seeds.back();
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
    transition.authorization_base = statement.roster_authorization_base;
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

std::unique_ptr<VerificationFixture> MakeVerificationFixture(
    int32_t target_height = 2000)
{
    // A by-value return leaves fixture-sized temporaries in MSVC caller frames.
    auto fixture_storage = std::make_unique<VerificationFixture>();
    auto& fixture = *fixture_storage;
    fixture.chainlock.statement.height = target_height;
    fixture.chainlock.statement.block_hash = NonNullHash(9100);
    fixture.chainlock.statement.previous_chainlock_height =
        target_height - static_cast<int32_t>(PQ_CL_PERIOD);
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
    fixture.chainlock.statement.roster_authorization_base =
        RosterAuthorizationBaseIdentity{
            fixture.chainlock.statement.previous_chainlock_height,
            fixture.chainlock.statement.previous_chainlock_hash,
            NonNullHash(9098)};
    fixture.authorization.authorization_base =
        fixture.chainlock.statement.roster_authorization_base;
    fixture.authorization.reset_policy = ResetPolicy(fixture.schedule);
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

std::optional<PreparedChainLockVerification> PrepareWithDetachedRosters(
    const VerificationFixture& fixture,
    const FinalChainLock& chainlock,
    FrozenQuorumRostersPtr rosters,
    const RosterAuthorizationVerificationContext& authorization,
    ChainLockVerificationError* error)
{
    const auto roster_set{VerifiedRosterSet::Create(
        fixture.genesis_hash, std::move(rosters), error)};
    if (!roster_set) return std::nullopt;
    return PrepareFinalChainLockVerification(
        fixture.schedule, chainlock, *roster_set, authorization, error);
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

constexpr std::size_t DURABLE_HEADER_SIZE{sizeof(uint16_t) + 32};
constexpr std::size_t DESCRIPTOR_MEMBER_ROOT_OFFSET{164};
constexpr std::size_t DESCRIPTOR_CHILD_ROOT_OFFSET{196};
constexpr std::size_t MEMBER_ELIGIBLE_OFFSET{32};
constexpr std::size_t MEMBER_CHILD_PRESENT_OFFSET{33};
constexpr std::size_t MEMBER_CHILD_TREE_ID_OFFSET{90};

std::optional<std::array<std::size_t, ACTIVE_QUORUMS>>
DurableRosterOffsets(Span<const uint8_t> encoded)
{
    std::array<std::size_t, ACTIVE_QUORUMS> offsets{};
    std::size_t cursor{DURABLE_HEADER_SIZE};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if (cursor + DurableRosterContext::DESCRIPTOR_SIZE >
            encoded.size()) {
            return std::nullopt;
        }
        offsets[slot] = cursor;
        cursor += DurableRosterContext::DESCRIPTOR_SIZE;
        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            if (cursor + DurableRosterContext::MEMBER_MIN_SIZE >
                encoded.size()) {
                return std::nullopt;
            }
            const uint8_t has_child_root{
                encoded[cursor + MEMBER_CHILD_PRESENT_OFFSET]};
            if (has_child_root > 1) return std::nullopt;
            cursor += DurableRosterContext::MEMBER_MIN_SIZE;
            if (has_child_root != 0) {
                if (cursor + DurableRosterContext::CHILD_ROOT_SIZE >
                    encoded.size()) {
                    return std::nullopt;
                }
                cursor += DurableRosterContext::CHILD_ROOT_SIZE;
            }
        }
    }
    if (cursor != encoded.size()) return std::nullopt;
    return offsets;
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

BOOST_AUTO_TEST_CASE(durable_roster_context_roundtrip_and_strict_bounds)
{
    const auto fixture{MakeVerificationFixture()};
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &error)};
    BOOST_REQUIRE(roster_set);
    const auto prepared{PreparedChainLockContext::Create(
        fixture->schedule, fixture->chainlock.statement, roster_set,
        fixture->authorization, &error)};
    BOOST_REQUIRE(prepared);
    const auto durable{DurableRosterContext::Capture(*prepared)};

    const auto encoded{durable.Encode()};
    BOOST_CHECK_GE(encoded.size(),
                   DurableRosterContext::MIN_SERIALIZED_SIZE);
    BOOST_CHECK_LE(encoded.size(),
                   DurableRosterContext::MAX_SERIALIZED_SIZE);
    const auto decoded{DurableRosterContext::DecodeTrustedPersistence(
        encoded, &error)};
    BOOST_REQUIRE(decoded);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_CHECK(decoded->GenesisHash() == durable.GenesisHash());
    BOOST_CHECK(decoded->Rosters() == durable.Rosters());
    BOOST_CHECK(decoded->Encode() == encoded);

    auto truncated{encoded};
    truncated.pop_back();
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        truncated, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);

    auto trailing{encoded};
    trailing.push_back(0);
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        trailing, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);

    std::vector<uint8_t> oversized(
        DurableRosterContext::MAX_SERIALIZED_SIZE + 1, 0);
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        oversized, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);
}

BOOST_AUTO_TEST_CASE(durable_roster_context_rejects_noncanonical_content)
{
    const auto fixture{MakeVerificationFixture()};
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &error)};
    BOOST_REQUIRE(roster_set);
    const auto prepared{PreparedChainLockContext::Create(
        fixture->schedule, fixture->chainlock.statement, roster_set,
        fixture->authorization, &error)};
    BOOST_REQUIRE(prepared);
    const auto durable{DurableRosterContext::Capture(*prepared)};
    const auto encoded{durable.Encode()};
    const auto roster_offsets{DurableRosterOffsets(encoded)};
    BOOST_REQUIRE(roster_offsets);
    BOOST_REQUIRE(fixture->rosters[0].members[0].child_root);
    BOOST_REQUIRE(fixture->rosters[0].members[1].child_root);
    const std::size_t descriptor{(*roster_offsets)[0]};
    const std::size_t first_member{
        descriptor + DurableRosterContext::DESCRIPTOR_SIZE};
    const std::size_t second_member{
        first_member + DurableRosterContext::MEMBER_MAX_SIZE};

    auto wrong_format{encoded};
    ++wrong_format[0];
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        wrong_format, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);

    auto bad_descriptor{encoded};
    ++bad_descriptor[descriptor];
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        bad_descriptor, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_DESCRIPTOR);

    auto noncanonical_flag{encoded};
    noncanonical_flag[first_member + MEMBER_ELIGIBLE_OFFSET] = 2;
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        noncanonical_flag, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);

    auto noncanonical_presence{encoded};
    noncanonical_presence[
        first_member + MEMBER_CHILD_PRESENT_OFFSET] = 2;
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        noncanonical_presence, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ARGUMENT);

    auto bad_member_root{encoded};
    bad_member_root[descriptor + DESCRIPTOR_MEMBER_ROOT_OFFSET] ^= 1;
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        bad_member_root, &error));
    BOOST_CHECK(error == ChainLockVerificationError::MEMBER_ROOT_MISMATCH);

    auto bad_child_root{encoded};
    bad_child_root[descriptor + DESCRIPTOR_CHILD_ROOT_OFFSET] ^= 1;
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        bad_child_root, &error));
    BOOST_CHECK(error == ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);

    auto nonderived_tree_id{encoded};
    auto altered_rosters{fixture->rosters};
    auto& altered_roster{altered_rosters[0]};
    auto& altered_child{*altered_roster.members[0].child_root};
    const uint256 wrong_tree_id{NonNullHash(999'999)};
    BOOST_REQUIRE(wrong_tree_id != altered_child.commitment.tree_id);
    altered_child.commitment.tree_id = wrong_tree_id;
    altered_roster.descriptor.child_key_root =
        ComputeQuorumChildKeyRoot(fixture->genesis_hash, altered_roster);
    std::copy(wrong_tree_id.begin(), wrong_tree_id.end(),
              nonderived_tree_id.begin() + first_member +
                  MEMBER_CHILD_TREE_ID_OFFSET);
    std::copy(altered_roster.descriptor.child_key_root.begin(),
              altered_roster.descriptor.child_key_root.end(),
              nonderived_tree_id.begin() + descriptor +
                  DESCRIPTOR_CHILD_ROOT_OFFSET);
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        nonderived_tree_id, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER);

    BOOST_CHECK(!VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(altered_rosters),
        &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER);

    auto duplicate_member{encoded};
    std::copy_n(duplicate_member.begin() + first_member, 32,
                duplicate_member.begin() + second_member);
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        duplicate_member, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_MEMBER);

    auto duplicate_child_key{encoded};
    std::copy_n(
        duplicate_child_key.begin() + first_member +
            MEMBER_CHILD_TREE_ID_OFFSET,
        32,
        duplicate_child_key.begin() + second_member +
            MEMBER_CHILD_TREE_ID_OFFSET);
    BOOST_CHECK(!DurableRosterContext::DecodeTrustedPersistence(
        duplicate_child_key, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_CHILD_KEY);
}

BOOST_AUTO_TEST_CASE(durable_recovery_requires_explicit_trusted_path)
{
    auto fixture{MakeVerificationFixture(/*target_height=*/2025)};
    auto& statement{fixture->chainlock.statement};
    const RosterAuthorizationPriorState prior{
        NonNullHash(520'000), InitializationWindow(/*first_epoch=*/0)};
    statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    statement.roster_authorization_base = {
        statement.previous_chainlock_height,
        statement.previous_chainlock_hash,
        NonNullHash(520'001)};
    statement.roster_beacons = RecoveryWindow(
        fixture->rosters.front().descriptor.epoch,
        prior.window.active);
    statement.previous_btcc_cursor = {};
    statement.accepted_btcc_cursor = {};
    statement.btcc_advance = BTCCAdvance::KEEP;

    RosterAuthorizationVerificationContext recovery;
    recovery.admission = RosterAuthorizationAdmission::RECOVER;
    recovery.predecessor_height = statement.previous_chainlock_height;
    recovery.predecessor_block_hash = statement.previous_chainlock_hash;
    recovery.authorization_base = statement.roster_authorization_base;
    recovery.reset_policy = ResetPolicy(fixture->schedule);
    recovery.previous = prior;
    SealRosterAuthorization(fixture->genesis_hash, statement, recovery);

    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto beacon_hash{GetRosterBeaconCommitmentHash(
            fixture->genesis_hash,
            statement.roster_beacons.active.seeds[slot])};
        BOOST_REQUIRE(beacon_hash);
        fixture->rosters[slot].descriptor.roster_beacon_hash =
            *beacon_hash;
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, statement.height,
        statement.block_hash, descriptors);

    // The test-only canonical builder stands in for the production snapshot
    // builder. The durable decoder itself never receives that provenance.
    const auto canonical_recovery_set{
        ChainLockStoreTestContextFactory::CreateCanonicalRosterSet(
            fixture->genesis_hash,
            std::make_shared<const FrozenQuorumRosters>(
                fixture->rosters))};
    BOOST_REQUIRE(canonical_recovery_set);
    const auto recovery_prepared{PreparedChainLockContext::Create(
        fixture->schedule, statement, canonical_recovery_set,
        recovery)};
    BOOST_REQUIRE(recovery_prepared);
    const auto recovery_durable{
        DurableRosterContext::Capture(*recovery_prepared)};
    const auto recovery_bytes{recovery_durable.Encode()};

    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto durable{DurableRosterContext::DecodeTrustedPersistence(
        recovery_bytes, &error)};
    BOOST_REQUIRE(durable);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);

    const auto detached_recovery_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters))};
    BOOST_REQUIRE(detached_recovery_set);
    BOOST_CHECK(!detached_recovery_set->HasCanonicalBuildProvenance());

    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, statement, detached_recovery_set,
        recovery, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER_BEACON);

    RosterAuthorizationVerificationContext trusted;
    trusted.admission = RosterAuthorizationAdmission::TRUSTED_PERSISTENCE;
    trusted.predecessor_height = statement.previous_chainlock_height;
    trusted.predecessor_block_hash = statement.previous_chainlock_hash;
    const auto reloaded{PreparedChainLockContext::CreateFromTrustedPersistence(
        fixture->schedule, statement, *durable, trusted, &error)};
    BOOST_REQUIRE(reloaded);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_CHECK(!reloaded->RosterSetPtr()->HasCanonicalBuildProvenance());
    BOOST_CHECK(reloaded->Rosters() == fixture->rosters);

    BOOST_CHECK(!PreparedChainLockContext::CreateFromTrustedPersistence(
        fixture->schedule, statement, *durable, recovery, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
}

BOOST_AUTO_TEST_CASE(preparation_recomputes_roots_context_and_canonical_mapping)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::INVALID_ARGUMENT};
    auto prepared = PrepareWithDetachedRosters(
        *fixture, fixture->chainlock,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
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
        BOOST_CHECK(!PrepareWithDetachedRosters(
            *bad_member_root, bad_member_root->chainlock,
            std::make_shared<const FrozenQuorumRosters>(
                bad_member_root->rosters),
            bad_member_root->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::MEMBER_ROOT_MISMATCH);
    }

    {
        auto bad_child_root = MakeVerificationFixture();
        bad_child_root->rosters[0].descriptor.child_key_root.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareWithDetachedRosters(
            *bad_child_root, bad_child_root->chainlock,
            std::make_shared<const FrozenQuorumRosters>(
                bad_child_root->rosters),
            bad_child_root->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);
    }

    {
        auto bad_context = MakeVerificationFixture();
        bad_context->chainlock.statement.quorum_context_hash.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareWithDetachedRosters(
            *bad_context, bad_context->chainlock,
            std::make_shared<const FrozenQuorumRosters>(
                bad_context->rosters),
            bad_context->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
    }

    {
        auto bad_index = MakeVerificationFixture();
        ClearMember(bad_index->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        SetMember(bad_index->chainlock.signer_bitmaps[0], QUORUM_MIN_VALID);
        BOOST_REQUIRE(bad_index->chainlock.IsStructurallyValid());
        BOOST_CHECK(!PrepareWithDetachedRosters(
            *bad_index, bad_index->chainlock,
            std::make_shared<const FrozenQuorumRosters>(bad_index->rosters),
            bad_index->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::INVALID_SIGNER);
    }

    {
        auto bad_bitmap = MakeVerificationFixture();
        ClearMember(bad_bitmap->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        BOOST_CHECK(!PrepareWithDetachedRosters(
            *bad_bitmap, bad_bitmap->chainlock,
            std::make_shared<const FrozenQuorumRosters>(
                bad_bitmap->rosters),
            bad_bitmap->authorization, &error));
        BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHAINLOCK);
    }
}

BOOST_AUTO_TEST_CASE(preparation_rejects_mutated_child_membership_witness)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto bad_sibling = MakeVerificationFixture();
    bad_sibling->chainlock.signatures[0].key_proof.siblings[0]
        .begin()[0] ^= 1;
    BOOST_CHECK(!PrepareWithDetachedRosters(
        *bad_sibling, bad_sibling->chainlock,
        std::make_shared<const FrozenQuorumRosters>(bad_sibling->rosters),
        bad_sibling->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);

    auto bad_public_key = MakeVerificationFixture();
    bad_public_key->chainlock.signatures[0].key_proof.public_key[0] ^= 1;
    BOOST_CHECK(!PrepareWithDetachedRosters(
        *bad_public_key, bad_public_key->chainlock,
        std::make_shared<const FrozenQuorumRosters>(
            bad_public_key->rosters),
        bad_public_key->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);
}

BOOST_AUTO_TEST_CASE(preparation_rejects_duplicate_members_and_child_keys)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto duplicate_member = MakeVerificationFixture();
    duplicate_member->rosters[0].members.back().pro_tx_hash =
        duplicate_member->rosters[0].members[QUORUM_SIZE - 2].pro_tx_hash;
    BOOST_CHECK(!PrepareWithDetachedRosters(
        *duplicate_member, duplicate_member->chainlock,
        std::make_shared<const FrozenQuorumRosters>(
            duplicate_member->rosters),
        duplicate_member->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_MEMBER);

    auto duplicate_key = MakeVerificationFixture();
    duplicate_key->rosters[0].members[1]
        .child_root->commitment.tree_id =
        duplicate_key->rosters[0].members[0]
            .child_root->commitment.tree_id;
    BOOST_CHECK(!PrepareWithDetachedRosters(
        *duplicate_key, duplicate_key->chainlock,
        std::make_shared<const FrozenQuorumRosters>(
            duplicate_key->rosters),
        duplicate_key->authorization, &error));
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

BOOST_AUTO_TEST_CASE(success_cache_is_exact_bounded_and_failure_preserving)
{
    constexpr std::size_t CHECK_COUNT{8};
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = 91 + i;
    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));

    std::array<scheduled_wots::Message, CHECK_COUNT> messages;
    std::array<scheduled_wots::Signature, CHECK_COUNT> signatures;
    for (std::size_t i{0}; i < CHECK_COUNT; ++i) {
        for (std::size_t byte{0}; byte < messages[i].size(); ++byte) {
            messages[i][byte] = static_cast<uint8_t>(17 * i + byte);
        }
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *secret_key, static_cast<uint8_t>(i), messages[i],
            signatures[i]));
    }

    const auto make_check = [&](std::size_t index) {
        return ScheduledWOTSCheck{
            public_key, static_cast<uint8_t>(index), messages[index],
            signatures[index]};
    };
    const auto make_batch = [&] {
        std::vector<ScheduledWOTSCheck> checks;
        checks.reserve(CHECK_COUNT);
        for (std::size_t i{0}; i < CHECK_COUNT; ++i) {
            checks.push_back(make_check(i));
        }
        return checks;
    };

    {
        ChainLockVerifier verifier{/*worker_threads=*/2, /*batch_size=*/1,
                                   /*success_cache_capacity=*/16};
        auto bad_batch{make_batch()};
        auto bad_signature{signatures[0]};
        bad_signature[0] ^= 1;
        bad_batch[0] = ScheduledWOTSCheck{
            public_key, /*leaf_index=*/0, messages[0], bad_signature};

        const uint64_t before{verifier.GetSuccessCacheMissCountForTesting()};
        BOOST_CHECK(!verifier.VerifyChecks(std::move(bad_batch)));
        BOOST_CHECK(bad_batch.empty());

        // Irrespective of where randomized preflight finds the bad member,
        // every successful check already performed is retained. Completing
        // the original valid set therefore performs each success exactly once
        // across both calls, plus the one failed mutation.
        for (std::size_t i{0}; i < CHECK_COUNT; ++i) {
            std::vector<ScheduledWOTSCheck> check;
            check.push_back(make_check(i));
            BOOST_CHECK(verifier.VerifyChecks(std::move(check)));
        }
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - before,
            CHECK_COUNT + 1);

        const uint64_t repeat_before{
            verifier.GetSuccessCacheMissCountForTesting()};
        auto repeated_bad_batch{make_batch()};
        repeated_bad_batch[0] = ScheduledWOTSCheck{
            public_key, /*leaf_index=*/0, messages[0], bad_signature};
        BOOST_CHECK(!verifier.VerifyChecks(std::move(repeated_bad_batch)));
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - repeat_before,
            1U);

        const uint64_t valid_repeat_before{
            verifier.GetSuccessCacheMissCountForTesting()};
        BOOST_CHECK(verifier.VerifyChecks(make_batch()));
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - valid_repeat_before,
            0U);

        // No component of the exact check identity may borrow the cached
        // success, and failures are never cached.
        auto wrong_message{messages[0]};
        wrong_message[0] ^= 1;
        for (int retry{0}; retry < 2; ++retry) {
            const uint64_t mismatch_before{
                verifier.GetSuccessCacheMissCountForTesting()};
            std::vector<ScheduledWOTSCheck> mismatch;
            mismatch.emplace_back(public_key, /*leaf_index=*/0,
                                  wrong_message, signatures[0]);
            BOOST_CHECK(!verifier.VerifyChecks(std::move(mismatch)));
            BOOST_CHECK_EQUAL(
                verifier.GetSuccessCacheMissCountForTesting() - mismatch_before,
                1U);
        }

        std::vector<ScheduledWOTSCheck> wrong_leaf;
        wrong_leaf.emplace_back(public_key, /*leaf_index=*/1, messages[0],
                                signatures[0]);
        BOOST_CHECK(!verifier.VerifyChecks(std::move(wrong_leaf)));

        auto wrong_public_key{public_key};
        wrong_public_key[0] ^= 1;
        std::vector<ScheduledWOTSCheck> wrong_key;
        wrong_key.emplace_back(wrong_public_key, /*leaf_index=*/0,
                               messages[0], signatures[0]);
        BOOST_CHECK(!verifier.VerifyChecks(std::move(wrong_key)));
    }

    {
        ChainLockVerifier verifier{/*worker_threads=*/0, /*batch_size=*/1,
                                   /*success_cache_capacity=*/2};
        std::vector<ScheduledWOTSCheck> first;
        first.push_back(make_check(0));
        BOOST_CHECK(verifier.VerifyChecks(std::move(first)));

        std::vector<ScheduledWOTSCheck> second;
        second.push_back(make_check(1));
        BOOST_CHECK(verifier.VerifyChecks(std::move(second)));

        std::vector<ScheduledWOTSCheck> third;
        third.push_back(make_check(2));
        BOOST_CHECK(verifier.VerifyChecks(std::move(third)));

        const uint64_t eviction_before{
            verifier.GetSuccessCacheMissCountForTesting()};
        std::vector<ScheduledWOTSCheck> retained;
        retained.push_back(make_check(1));
        BOOST_CHECK(verifier.VerifyChecks(std::move(retained)));
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - eviction_before,
            0U);

        std::vector<ScheduledWOTSCheck> evicted;
        evicted.push_back(make_check(0));
        BOOST_CHECK(verifier.VerifyChecks(std::move(evicted)));
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - eviction_before,
            1U);
    }

    BOOST_CHECK_THROW(
        ChainLockVerifier(/*worker_threads=*/0, /*batch_size=*/1,
                          /*success_cache_capacity=*/0),
        std::invalid_argument);
    BOOST_CHECK_THROW(
        ChainLockVerifier(
            /*worker_threads=*/0, /*batch_size=*/1,
            ChainLockVerifier::DEFAULT_SUCCESS_CACHE_CAPACITY + 1),
        std::invalid_argument);
    BOOST_CHECK_THROW(
        ChainLockVerifier(/*worker_threads=*/0, /*batch_size=*/1,
                          std::numeric_limits<std::size_t>::max()),
        std::invalid_argument);
    memory_cleanse(seed.data(), seed.size());
}

BOOST_AUTO_TEST_CASE(success_cache_pins_first_valid_signature_per_statement)
{
    constexpr std::size_t CACHE_CAPACITY{2};
    constexpr std::size_t VARIANT_COUNT{6};
    scheduled_wots::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) seed[i] = 37 + i;
    auto secret_key{scheduled_wots::GenerateSecretKey(seed)};
    BOOST_REQUIRE(secret_key);
    scheduled_wots::PublicKey public_key{};
    BOOST_REQUIRE(secret_key->GetPublicKey(public_key));
    scheduled_wots::Message message{};
    message[0] = 19;
    std::array<scheduled_wots::Signature, CACHE_CAPACITY + 1> originals;
    for (std::size_t leaf{0}; leaf < originals.size(); ++leaf) {
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *secret_key, leaf, message, originals[leaf]));
    }

    std::array<scheduled_wots::Signature, VARIANT_COUNT> variants;
    for (std::size_t i{0}; i < variants.size(); ++i) {
        // SK.prf changes the randomizer without changing the public tree, so
        // these are valid Byzantine encodings of one verification statement.
        seed[scheduled_wots::N] ^= static_cast<uint8_t>(i + 1);
        auto variant_key{scheduled_wots::GenerateSecretKey(seed)};
        seed[scheduled_wots::N] ^= static_cast<uint8_t>(i + 1);
        BOOST_REQUIRE(variant_key);
        scheduled_wots::PublicKey variant_public_key{};
        BOOST_REQUIRE(variant_key->GetPublicKey(variant_public_key));
        BOOST_REQUIRE(variant_public_key == public_key);
        BOOST_REQUIRE(scheduled_wots::SignDeterministic(
            *variant_key, 0, message, variants[i]));
        BOOST_REQUIRE(variants[i] != originals[0]);
        for (std::size_t previous{0}; previous < i; ++previous) {
            BOOST_REQUIRE(variants[i] != variants[previous]);
        }
    }
    memory_cleanse(seed.data(), seed.size());

    const auto check_one = [&](ChainLockVerifier& verifier, uint8_t leaf,
                               const scheduled_wots::Signature& signature,
                               bool expected_valid, uint64_t expected_misses) {
        const uint64_t before{verifier.GetSuccessCacheMissCountForTesting()};
        std::vector<ScheduledWOTSCheck> checks;
        checks.emplace_back(public_key, leaf, message, signature);
        BOOST_CHECK_EQUAL(verifier.VerifyChecks(std::move(checks)),
                          expected_valid);
        BOOST_CHECK(checks.empty());
        BOOST_CHECK_EQUAL(
            verifier.GetSuccessCacheMissCountForTesting() - before,
            expected_misses);
    };
    const auto variant_batch = [&] {
        std::vector<ScheduledWOTSCheck> checks;
        for (const auto& signature : variants) {
            checks.emplace_back(public_key, 0, message, signature);
        }
        return checks;
    };

    for (const std::size_t worker_threads : {0U, 2U}) {
        BOOST_TEST_CONTEXT("worker_threads=" << worker_threads) {
            ChainLockVerifier verifier{worker_threads, /*batch_size=*/1,
                                       CACHE_CAPACITY};
            check_one(verifier, 0, originals[0], true, 1);
            check_one(verifier, 1, originals[1], true, 1);

            // More variants than cache slots and preflight jobs exercise the
            // queue without letting alternate successes evict either base.
            for (int retry{0}; retry < 2; ++retry) {
                const uint64_t before{
                    verifier.GetSuccessCacheMissCountForTesting()};
                BOOST_CHECK(verifier.VerifyChecks(variant_batch()));
                BOOST_CHECK_EQUAL(
                    verifier.GetSuccessCacheMissCountForTesting() - before,
                    VARIANT_COUNT);
                check_one(verifier, 0, originals[0], true, 0);
                check_one(verifier, 1, originals[1], true, 0);
            }

            auto invalid_variant{variants[0]};
            invalid_variant[0] ^= 1;
            auto invalid_new_base{originals[2]};
            invalid_new_base[0] ^= 1;
            for (int retry{0}; retry < 2; ++retry) {
                check_one(verifier, 0, invalid_variant, false, 1);
                check_one(verifier, 2, invalid_new_base, false, 1);
            }
            check_one(verifier, 0, originals[0], true, 0);
            check_one(verifier, 1, originals[1], true, 0);

            check_one(verifier, 2, originals[2], true, 1);
            check_one(verifier, 1, originals[1], true, 0);
            check_one(verifier, 0, originals[0], true, 1);

            ChainLockVerifier competing{worker_threads, /*batch_size=*/1,
                                        CACHE_CAPACITY};
            std::promise<void> start;
            const auto start_signal{start.get_future().share()};
            std::array<bool, VARIANT_COUNT> results{};
            std::array<std::thread, VARIANT_COUNT> threads;
            for (std::size_t i{0}; i < variants.size(); ++i) {
                threads[i] = std::thread([&, i, start_signal] {
                    start_signal.wait();
                    std::vector<ScheduledWOTSCheck> checks;
                    checks.emplace_back(public_key, 0, message, variants[i]);
                    results[i] = competing.VerifyChecks(std::move(checks));
                });
            }
            start.set_value();
            for (auto& thread : threads) thread.join();
            BOOST_CHECK(std::all_of(results.begin(), results.end(),
                                    [](bool valid) { return valid; }));
            // Singleton preflights race first insertion without acquiring
            // queue control; exactly one successful encoding must survive.
            std::size_t hits{0};
            for (const auto& signature : variants) {
                const uint64_t before{
                    competing.GetSuccessCacheMissCountForTesting()};
                std::vector<ScheduledWOTSCheck> checks;
                checks.emplace_back(public_key, 0, message, signature);
                BOOST_CHECK(competing.VerifyChecks(std::move(checks)));
                const uint64_t misses{
                    competing.GetSuccessCacheMissCountForTesting() - before};
                BOOST_CHECK_LE(misses, 1U);
                if (misses == 0) ++hits;
            }
            BOOST_CHECK_EQUAL(hits, 1U);
        }
    }
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
    BOOST_CHECK(PrepareWithDetachedRosters(
        *fixture, fixture->chainlock,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        fixture->authorization, &error));

    // A syntactically correct state-hash edge is not sufficient for LIVE:
    // the verifier must receive and recheck the exact external policy facts.
    auto missing_normal_policy{fixture->authorization};
    missing_normal_policy.normal_input.reset();
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        missing_normal_policy, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto missing_reset_policy{fixture->authorization};
    missing_reset_policy.reset_policy.reset();
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, fixture->chainlock.statement,
        missing_reset_policy, &error));
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
    keep_authorization.authorization_base =
        keep_statement.roster_authorization_base;
    keep_authorization.reset_policy = ResetPolicy(fixture->schedule);
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

    fixture->chainlock.selected_quorum_mask = 0b1011;
    fixture->chainlock.signer_bitmaps[3] =
        fixture->chainlock.signer_bitmaps[2];
    fixture->chainlock.signer_bitmaps[2].fill(0);
    BOOST_REQUIRE(fixture->chainlock.IsStructurallyValid());
    BOOST_CHECK(!PrepareWithDetachedRosters(
        *fixture, fixture->chainlock,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
}

BOOST_AUTO_TEST_CASE(initialization_and_recovery_require_explicit_admission)
{
    auto fixture{MakeVerificationFixture()};
    auto statement{fixture->chainlock.statement};
    statement.height = 865;
    statement.block_hash = NonNullHash(9101);
    statement.previous_chainlock_height = 864;
    statement.previous_chainlock_hash = NonNullHash(9102);
    statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    statement.roster_authorization_base = {};
    statement.roster_beacons = InitializationWindow(/*first_epoch=*/0);
    statement.previous_btcc_cursor = {};
    statement.accepted_btcc_cursor = BTCCursor{
        statement.height, statement.block_hash, NonNullHash(9103)};
    statement.btcc_advance = BTCCAdvance::ADVANCE;

    RosterAuthorizationVerificationContext initialize;
    initialize.admission = RosterAuthorizationAdmission::INITIALIZE;
    initialize.predecessor_height = statement.previous_chainlock_height;
    initialize.predecessor_block_hash = statement.previous_chainlock_hash;
    initialize.reset_policy = ResetPolicy(fixture->schedule);
    SealRosterAuthorization(fixture->genesis_hash, statement, initialize);
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto initialize_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, initialize, &error)};
    BOOST_REQUIRE(initialize_mask);
    BOOST_CHECK_EQUAL(*initialize_mask, 0b1111);
    BOOST_CHECK(statement.roster_beacons.active.recovery_authority_source
                    .normal_beacon ==
                statement.roster_beacons.active.seeds.back());

    auto ordinary_live{initialize};
    ordinary_live.admission = RosterAuthorizationAdmission::LIVE;
    ordinary_live.previous = RosterAuthorizationPriorState{
        statement.roster_authorization_state_hash,
        statement.roster_beacons};
    ordinary_live.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            statement, *ordinary_live.previous);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, ordinary_live, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    const RosterAuthorizationBaseIdentity initialization_base{
        statement.height, statement.block_hash,
        GetLogicalChainLockId(fixture->genesis_hash, statement)};
    const RosterAuthorizationPriorState initialization_prior{
        statement.roster_authorization_state_hash,
        statement.roster_beacons};

    statement.height = 2025;
    statement.block_hash = NonNullHash(9201);
    statement.previous_chainlock_height = 2020;
    statement.previous_chainlock_hash = NonNullHash(9202);
    statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    statement.roster_authorization_base = initialization_base;
    statement.roster_beacons = RecoveryWindow(
        /*first_epoch=*/4, initialization_prior.window.active);
    statement.previous_btcc_cursor = {};
    statement.accepted_btcc_cursor = {};
    statement.btcc_advance = BTCCAdvance::KEEP;
    auto recover{initialize};
    recover.admission = RosterAuthorizationAdmission::RECOVER;
    recover.predecessor_height = statement.previous_chainlock_height;
    recover.predecessor_block_hash = statement.previous_chainlock_hash;
    recover.authorization_base = initialization_base;
    recover.previous = initialization_prior;
    recover.normal_input.reset();
    SealRosterAuthorization(fixture->genesis_hash, statement, recover);
    const auto recovery_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, recover, &error)};
    BOOST_REQUIRE(recovery_mask);
    BOOST_CHECK_EQUAL(*recovery_mask, 0b1111);
    BOOST_CHECK(statement.roster_beacons.active.recovery_authority_source ==
                initialization_prior.window.active
                    .recovery_authority_source);

    auto later_initialize_statement{statement};
    later_initialize_statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    later_initialize_statement.roster_beacons =
        InitializationWindow(/*first_epoch=*/4);
    later_initialize_statement.roster_authorization_base = {};
    later_initialize_statement.accepted_btcc_cursor = BTCCursor{
        later_initialize_statement.height,
        later_initialize_statement.block_hash, NonNullHash(9203)};
    later_initialize_statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto later_initialize{initialize};
    later_initialize.predecessor_height =
        later_initialize_statement.previous_chainlock_height;
    later_initialize.predecessor_block_hash =
        later_initialize_statement.previous_chainlock_hash;
    SealRosterAuthorization(fixture->genesis_hash,
                            later_initialize_statement,
                            later_initialize);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, later_initialize_statement,
        later_initialize, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto recovery_as_live{recover};
    recovery_as_live.admission = RosterAuthorizationAdmission::LIVE;
    recovery_as_live.normal_input =
        test::MakeSyntheticNormalRosterAuthorizationInput(
            statement, *recovery_as_live.previous);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, recovery_as_live, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto off_target_statement{statement};
    off_target_statement.height += 5;
    off_target_statement.block_hash = NonNullHash(9302);
    off_target_statement.previous_chainlock_height += 5;
    off_target_statement.previous_chainlock_hash = NonNullHash(9303);
    auto off_target_recovery{recover};
    off_target_recovery.predecessor_height =
        off_target_statement.previous_chainlock_height;
    off_target_recovery.predecessor_block_hash =
        off_target_statement.previous_chainlock_hash;
    SealRosterAuthorization(fixture->genesis_hash,
                            off_target_statement,
                            off_target_recovery);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, off_target_statement,
        off_target_recovery, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
    auto missing_prior{recover};
    missing_prior.previous.reset();
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, missing_prior, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto null_base_statement{statement};
    null_base_statement.roster_authorization_base = {};
    auto null_base{recover};
    null_base.authorization_base = {};
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, null_base_statement, null_base, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHAINLOCK);

    auto wrong_base{recover};
    wrong_base.authorization_base.logical_id = NonNullHash(9400);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, wrong_base, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto wrong_prior_state{recover};
    wrong_prior_state.previous->state_hash = NonNullHash(9401);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, wrong_prior_state, &error));
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
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, fixture->chainlock.statement, roster_set,
        fixture->authorization, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER_BEACON);
}

BOOST_AUTO_TEST_CASE(initialization_requires_all_retained_rotation_rosters)
{
    auto fixture{MakeVerificationFixture(/*target_height=*/2025)};
    auto& statement{fixture->chainlock.statement};
    statement.previous_chainlock_height = 2024;
    statement.previous_chainlock_hash = NonNullHash(9450);
    statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    statement.roster_authorization_base = {};
    statement.roster_beacons = InitializationWindow(
        fixture->rosters.front().descriptor.epoch);
    statement.previous_btcc_cursor = {};
    statement.accepted_btcc_cursor = BTCCursor{
        statement.height, statement.block_hash, NonNullHash(9451)};
    statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto& retained{fixture->rosters[1]};
    constexpr std::size_t LAST_VALID_MEMBER{QUORUM_MIN_VALID - 1};
    retained.members[LAST_VALID_MEMBER].eligible = false;
    ClearMember(retained.descriptor.valid_members, LAST_VALID_MEMBER);
    retained.descriptor.valid_count = QUORUM_MIN_VALID - 1;

    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        const auto beacon_hash{GetRosterBeaconCommitmentHash(
            fixture->genesis_hash,
            statement.roster_beacons.active.seeds[slot])};
        BOOST_REQUIRE(beacon_hash);
        fixture->rosters[slot].descriptor.roster_beacon_hash =
            *beacon_hash;
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    statement.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, statement.height,
        statement.block_hash, descriptors);

    RosterAuthorizationVerificationContext initialize;
    initialize.admission = RosterAuthorizationAdmission::INITIALIZE;
    initialize.predecessor_height = statement.previous_chainlock_height;
    initialize.predecessor_block_hash = statement.previous_chainlock_hash;
    initialize.reset_policy = RosterResetVerificationPolicy{
        fixture->schedule,
        BTCCScheduleConfig{.candidate_origin = 865},
        /*activation_predecessor_height=*/2024};
    SealRosterAuthorization(fixture->genesis_hash, statement, initialize);

    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto roster_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &error)};
    BOOST_REQUIRE(roster_set);
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, statement, roster_set, initialize, &error));
    BOOST_CHECK_EQUAL(static_cast<int>(error),
                      static_cast<int>(ChainLockVerificationError::INVALID_ROSTER));
}

BOOST_AUTO_TEST_CASE(recovery_binds_exact_durable_source)
{
    auto fixture{MakeVerificationFixture(/*target_height=*/2025)};
    auto& statement{fixture->chainlock.statement};
    auto prior_window{InitializationWindow(/*first_epoch=*/0)};
    const RosterAuthorizationPriorState prior{
        NonNullHash(500'000), std::move(prior_window)};
    const RosterAuthorizationBaseIdentity base{
        865, NonNullHash(500'001), NonNullHash(500'002)};

    statement.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    statement.roster_authorization_base = base;
    statement.roster_beacons = RecoveryWindow(
        /*first_epoch=*/4, prior.window.active);
    statement.previous_btcc_cursor = {};
    statement.accepted_btcc_cursor = {};
    statement.btcc_advance = BTCCAdvance::KEEP;

    RosterAuthorizationVerificationContext recovery;
    recovery.admission = RosterAuthorizationAdmission::RECOVER;
    recovery.predecessor_height = statement.previous_chainlock_height;
    recovery.predecessor_block_hash = statement.previous_chainlock_hash;
    recovery.authorization_base = base;
    recovery.reset_policy = ResetPolicy(fixture->schedule);
    recovery.previous = prior;
    SealRosterAuthorization(fixture->genesis_hash, statement, recovery);

    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    const auto mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, statement, recovery, &error)};
    BOOST_REQUIRE(mask);
    BOOST_CHECK_EQUAL(*mask, 0b1111);
    BOOST_CHECK(!recovery.normal_input);

    auto different_source{prior.window.active};
    different_source.recovery_authority_source.normal_beacon
        .future_btc_hash = NonNullHash(500'003);
    auto wrong_source_statement{statement};
    wrong_source_statement.roster_beacons = RecoveryWindow(
        /*first_epoch=*/4, different_source);
    SealRosterAuthorization(fixture->genesis_hash,
                            wrong_source_statement, recovery);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, wrong_source_statement, recovery,
        &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto wrong_advance{statement};
    wrong_advance.accepted_btcc_cursor = BTCCursor{
        statement.height, statement.block_hash, NonNullHash(500'005)};
    wrong_advance.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(wrong_advance.IsStructurallyValid());
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, wrong_advance, recovery, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    // Recovery contexts are accepted only after the canonical builder has
    // reconstructed the roster from the source and minted its capability.
    const auto detached_set{VerifiedRosterSet::Create(
        fixture->genesis_hash,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        &error)};
    BOOST_REQUIRE(detached_set);
    BOOST_CHECK(!PreparedChainLockContext::Create(
        fixture->schedule, statement, detached_set, recovery, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_ROSTER_BEACON);
}

BOOST_AUTO_TEST_CASE(later_recovery_uses_exact_prior_state_without_precommit)
{
    auto fixture{MakeVerificationFixture()};
    const auto policy{ResetPolicy(fixture->schedule)};
    const auto first_target{CanonicalRosterRecoveryTargetHeight(
        policy.chainlock_schedule, policy.btcc_schedule,
        /*epoch=*/7)};
    const auto retry_target{CanonicalRosterRecoveryTargetHeight(
        policy.chainlock_schedule, policy.btcc_schedule,
        /*epoch=*/11)};
    BOOST_REQUIRE(first_target);
    BOOST_REQUIRE(retry_target);

    const RosterAuthorizationPriorState initialization_prior{
        NonNullHash(510'000), InitializationWindow(/*first_epoch=*/0)};
    ChainLockStatement first{fixture->chainlock.statement};
    first.height = *first_target;
    first.block_hash = NonNullHash(510'001);
    first.previous_chainlock_height = *first_target -
        static_cast<int32_t>(PQ_CL_PERIOD);
    first.previous_chainlock_hash = NonNullHash(510'002);
    first.roster_transition =
        RosterAuthorizationTransitionKind::RECOVER;
    first.roster_authorization_base = RosterAuthorizationBaseIdentity{
        865, NonNullHash(510'003), NonNullHash(510'004)};
    first.roster_beacons = RecoveryWindow(
        /*first_epoch=*/4, initialization_prior.window.active);
    first.previous_btcc_cursor = {};
    first.accepted_btcc_cursor = {};
    first.btcc_advance = BTCCAdvance::KEEP;

    RosterAuthorizationVerificationContext first_recovery;
    first_recovery.admission = RosterAuthorizationAdmission::RECOVER;
    first_recovery.predecessor_height =
        first.previous_chainlock_height;
    first_recovery.predecessor_block_hash =
        first.previous_chainlock_hash;
    first_recovery.authorization_base =
        first.roster_authorization_base;
    first_recovery.reset_policy = policy;
    first_recovery.previous = initialization_prior;
    SealRosterAuthorization(fixture->genesis_hash, first,
                            first_recovery);

    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    BOOST_REQUIRE(ValidateRosterAuthorizationState(
        fixture->genesis_hash, first, first_recovery, &error));

    const RosterAuthorizationPriorState first_prior{
        first.roster_authorization_state_hash, first.roster_beacons};
    ChainLockStatement retry{first};
    retry.height = *retry_target;
    retry.block_hash = NonNullHash(510'005);
    retry.previous_chainlock_height = *retry_target -
        static_cast<int32_t>(PQ_CL_PERIOD);
    retry.previous_chainlock_hash = NonNullHash(510'006);
    retry.roster_authorization_base = RosterAuthorizationBaseIdentity{
        first.height, first.block_hash,
        GetLogicalChainLockId(fixture->genesis_hash, first)};
    retry.roster_beacons = RecoveryWindow(
        /*first_epoch=*/8, first_prior.window.active);

    RosterAuthorizationVerificationContext retry_recovery;
    retry_recovery.admission = RosterAuthorizationAdmission::RECOVER;
    retry_recovery.predecessor_height =
        retry.previous_chainlock_height;
    retry_recovery.predecessor_block_hash =
        retry.previous_chainlock_hash;
    retry_recovery.authorization_base = retry.roster_authorization_base;
    retry_recovery.reset_policy = policy;
    retry_recovery.previous = first_prior;
    SealRosterAuthorization(fixture->genesis_hash, retry,
                            retry_recovery);

    const auto retry_mask{ValidateRosterAuthorizationState(
        fixture->genesis_hash, retry, retry_recovery, &error)};
    BOOST_REQUIRE(retry_mask);
    BOOST_CHECK_EQUAL(*retry_mask, 0b1111);
    BOOST_CHECK(retry.roster_beacons.active.recovery_authority_source ==
                first_prior.window.active.recovery_authority_source);
    BOOST_CHECK(retry.btcc_advance == BTCCAdvance::KEEP);
    BOOST_CHECK(!retry_recovery.normal_input);

    auto stale_prior{retry_recovery};
    stale_prior.previous = initialization_prior;
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, retry, stale_prior, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);

    auto wrong_base{retry_recovery};
    wrong_base.authorization_base.logical_id = NonNullHash(510'007);
    BOOST_CHECK(!ValidateRosterAuthorizationState(
        fixture->genesis_hash, retry, wrong_base, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_AUTHORIZATION);
}

BOOST_AUTO_TEST_CASE(prepared_verifier_reports_bad_signature_after_cheap_checks)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto prepared{PrepareWithDetachedRosters(
        *fixture, fixture->chainlock,
        std::make_shared<const FrozenQuorumRosters>(fixture->rosters),
        fixture->authorization, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    ChainLockVerifier verifier{/*worker_threads=*/0};
    BOOST_CHECK(!verifier.VerifyChecks(
        std::move(prepared->checks)));
}

BOOST_AUTO_TEST_SUITE_END()
