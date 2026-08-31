// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_signer.h>

#include <test/pq_test_util.h>
#include <test/util/setup_common.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

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

RosterBeaconWindow NormalWindow(uint32_t first_epoch)
{
    RosterBeaconWindow window;
    RosterBeaconSeed shared;
    shared.anchor_kind = RosterBeaconAnchorKind::NORMAL;
    shared.state = RosterBeaconState::READY;
    shared.anchor_cursor = BTCCursor{
        10'000, NonNullHash(100'000), NonNullHash(200'000)};
    shared.anchor_btc_height = 800'000;
    shared.future_btc_hash = NonNullHash(300'000);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto seed{shared};
        seed.epoch = first_epoch + static_cast<uint32_t>(slot);
        window.active.seeds[slot] = std::move(seed);
    }
    window.next.epoch = first_epoch + ACTIVE_QUORUMS;
    return window;
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

struct SignerFixture {
    uint256 genesis_hash{NonNullHash(8001)};
    uint256 local_pro_tx_hash{NonNullHash(8003)};
    ChainLockScheduleConfig schedule{.epoch_origin = 1440};
    ChainLockStatement statement;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    RosterAuthorizationVerificationContext authorization;
    std::optional<scheduled_wots::SecretKey> child_secret_key;
    ChildKeyProof child_key_proof;
};

std::unique_ptr<SignerFixture> MakeFixture()
{
    // A by-value return leaves fixture-sized temporaries in MSVC caller frames.
    auto fixture{std::make_unique<SignerFixture>()};
    fixture->statement.height = 2305;
    fixture->statement.block_hash = NonNullHash(8100);
    fixture->statement.previous_chainlock_height = 2300;
    fixture->statement.previous_chainlock_hash = NonNullHash(8099);
    fixture->statement.payment_probation_state_hash = NonNullHash(8101);
    fixture->statement.roster_beacons = NormalWindow(0);
    fixture->statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    fixture->authorization.admission =
        RosterAuthorizationAdmission::LIVE;
    fixture->authorization.predecessor_height =
        fixture->statement.previous_chainlock_height;
    fixture->authorization.predecessor_block_hash =
        fixture->statement.previous_chainlock_hash;
    fixture->authorization.previous = RosterAuthorizationPriorState{
        NonNullHash(8102), fixture->statement.roster_beacons};
    NormalRosterAuthorizationInput normal;
    normal.newest_epoch =
        fixture->statement.roster_beacons.active.seeds.back().epoch;
    normal.target_height = fixture->statement.height;
    normal.target_block_hash = fixture->statement.block_hash;
    normal.predecessor_height =
        fixture->statement.previous_chainlock_height;
    normal.predecessor_block_hash =
        fixture->statement.previous_chainlock_hash;
    normal.prior_authorization_height =
        fixture->statement.previous_chainlock_height;
    normal.prior_authorization_block_hash =
        fixture->statement.previous_chainlock_hash;
    normal.previous = *fixture->authorization.previous;
    normal.previous_btcc_cursor =
        fixture->statement.previous_btcc_cursor;
    normal.accepted_btcc_cursor =
        fixture->statement.accepted_btcc_cursor;
    normal.btcc_advance = fixture->statement.btcc_advance;
    normal.next_snapshot.epoch = normal.newest_epoch + 1;
    normal.next_snapshot.height = 2'592;
    fixture->authorization.normal_input = normal;
    const auto decision{DeriveNormalRosterAuthorizationDecision(
        fixture->genesis_hash, normal)};
    BOOST_REQUIRE(decision);
    BOOST_REQUIRE(decision->transition.kind ==
                  RosterAuthorizationTransitionKind::KEEP);
    fixture->statement.roster_beacons =
        decision->transition.new_window;
    fixture->statement.roster_authorization_state_hash =
        decision->state_hash;

    scheduled_wots::KeyGenerationSeed keygen_seed{};
    for (std::size_t i{0}; i < keygen_seed.size(); ++i) {
        keygen_seed[i] = static_cast<uint8_t>(i + 11);
    }
    auto child_secret_key{scheduled_wots::GenerateSecretKey(keygen_seed)};
    BOOST_REQUIRE(child_secret_key);
    ChildPublicKey child_public_key{};
    BOOST_REQUIRE(child_secret_key->GetPublicKey(child_public_key));
    fixture->child_secret_key.emplace(std::move(*child_secret_key));

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = static_cast<uint32_t>(slot);
        descriptor.base_height = 1440 + static_cast<int32_t>(slot * PQ_EPOCH_BLOCKS);
        descriptor.base_hash = NonNullHash(8200 + slot);
        descriptor.snapshot_height = descriptor.base_height - 288;
        descriptor.snapshot_hash = NonNullHash(8300 + slot);
        descriptor.roster_beacon_hash = *GetRosterBeaconCommitmentHash(
            fixture->genesis_hash,
            fixture->statement.roster_beacons.active.seeds[slot]);

        for (std::size_t member{0}; member < QUORUM_SIZE; ++member) {
            auto& roster_member{roster.members[member]};
            roster_member.pro_tx_hash =
                (slot == 0 && member == 0)
                    ? fixture->local_pro_tx_hash
                    : NonNullHash(20'000 + slot * QUORUM_SIZE + member);
            roster_member.eligible = member < QUORUM_MIN_VALID;
            if (!roster_member.eligible) continue;

            const ChildPublicKey public_key =
                (slot == 0 && member == 0)
                    ? child_public_key
                    : FakeChildKey(slot, member);
            const auto authorization{
                test::MakeSyntheticChildAuthorization(
                    fixture->genesis_hash, roster_member.pro_tx_hash,
                    descriptor.epoch, public_key,
                    1 + slot * QUORUM_SIZE + member)};
            roster_member.child_root = authorization.record;
            if (slot == 0 && member == 0) {
                fixture->child_key_proof = authorization.proof;
            }
            SetBit(descriptor.valid_members, member);
        }
        descriptor.valid_count = QUORUM_MIN_VALID;
        descriptor.member_root = ComputeQuorumMemberRoot(fixture->genesis_hash, roster);
        descriptor.child_key_root = ComputeQuorumChildKeyRoot(fixture->genesis_hash, roster);
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

PreparedChainLockContextPtr PrepareContext(const SignerFixture& fixture,
                                           ChainLockStatement statement)
{
    auto authorization{fixture.authorization};
    BOOST_REQUIRE(authorization.normal_input);
    auto& normal{*authorization.normal_input};
    normal.target_height = statement.height;
    normal.target_block_hash = statement.block_hash;
    normal.predecessor_height = statement.previous_chainlock_height;
    normal.predecessor_block_hash = statement.previous_chainlock_hash;
    normal.previous_btcc_cursor = statement.previous_btcc_cursor;
    normal.accepted_btcc_cursor = statement.accepted_btcc_cursor;
    normal.btcc_advance = statement.btcc_advance;
    const auto decision{DeriveNormalRosterAuthorizationDecision(
        fixture.genesis_hash, normal)};
    BOOST_REQUIRE(decision);
    BOOST_REQUIRE(decision->transition.kind == statement.roster_transition);
    statement.roster_beacons = decision->transition.new_window;
    statement.roster_authorization_state_hash = decision->state_hash;
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto context{PreparedChainLockContext::Create(
        fixture.genesis_hash, fixture.schedule, std::move(statement),
        std::make_shared<const FrozenQuorumRosters>(fixture.rosters),
        authorization, &error)};
    BOOST_REQUIRE(context);
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    return context;
}

PreparedChainLockContextPtr PrepareContext(const SignerFixture& fixture)
{
    return PrepareContext(fixture, fixture.statement);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_signer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signs_after_durable_reservation_and_replays_exact_share)
{
    auto fixture{MakeFixture()};
    const auto context{PrepareContext(*fixture)};
    llmq::CPQSignerJournal journal{m_path_root / "pq_chainlock_signer_replay"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash, fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::INVALID_ARGUMENT};

    const auto first{signer.Sign(
        *context, 0, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error)};
    BOOST_REQUIRE(first.share);
    BOOST_CHECK(!first.replayed);
    BOOST_CHECK(error == ChainLockSigningError::NONE);
    ChainLockVerificationError verify_error{ChainLockVerificationError::INVALID_ARGUMENT};
    BOOST_CHECK(VerifyChainLockShare(
        fixture->genesis_hash, fixture->schedule, *first.share,
        fixture->rosters,
        fixture->authorization, &verify_error));

    const auto replay{signer.Sign(
        *context, 0, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        journal.GetBranchLock(fixture->genesis_hash,
                              fixture->local_pro_tx_hash),
        &error)};
    BOOST_REQUIRE(replay.share);
    BOOST_CHECK(replay.replayed);
    BOOST_CHECK(*replay.share == *first.share);
}

BOOST_AUTO_TEST_CASE(refuses_equivocation_and_wrong_secret_key)
{
    auto fixture{MakeFixture()};
    const auto context{PrepareContext(*fixture)};
    llmq::CPQSignerJournal journal{m_path_root / "pq_chainlock_signer_conflict"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash, fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::NONE};
    BOOST_REQUIRE(signer.Sign(
        *context, 0, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error).share);

    auto competing{fixture->statement};
    competing.block_hash = NonNullHash(8999);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    competing.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, competing.height, competing.block_hash, descriptors);
    const auto competing_context{PrepareContext(*fixture, competing)};
    BOOST_CHECK(!signer.Sign(
        *competing_context, 0, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        journal.GetBranchLock(fixture->genesis_hash,
                              fixture->local_pro_tx_hash),
        &error).share);
    BOOST_CHECK(error == ChainLockSigningError::JOURNAL_CONFLICT);

    scheduled_wots::KeyGenerationSeed other_seed{};
    other_seed[0] = 9;
    other_seed[2 * scheduled_wots::N] = 7;
    auto other_secret_key{scheduled_wots::GenerateSecretKey(other_seed)};
    BOOST_REQUIRE(other_secret_key);
    auto other_height{fixture->statement};
    other_height.height += PQ_CL_PERIOD;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    other_height.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, other_height.height, other_height.block_hash, descriptors);
    const auto other_height_context{PrepareContext(*fixture, other_height)};
    BOOST_CHECK(!signer.Sign(
        *other_height_context, 0, 0,
        *other_secret_key, fixture->child_key_proof,
        journal.GetBranchLock(fixture->genesis_hash,
                              fixture->local_pro_tx_hash),
        &error).share);
    BOOST_CHECK(error == ChainLockSigningError::SECRET_KEY_MISMATCH);
}

BOOST_AUTO_TEST_CASE(rejects_wrong_operator_before_journal_reservation)
{
    auto fixture{MakeFixture()};
    const auto context{PrepareContext(*fixture)};
    llmq::CPQSignerJournal journal{
        m_path_root / "pq_chainlock_signer_unauthorized"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash,
        fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::NONE};
    BOOST_CHECK(!signer.Sign(
        *context, 3, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error).share);
    BOOST_CHECK(error == ChainLockSigningError::WRONG_OPERATOR);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, fixture->local_pro_tx_hash));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_schedule_before_leaf_reservation)
{
    auto fixture{MakeFixture()};
    const auto context{PrepareContext(*fixture)};
    llmq::CPQSignerJournal journal{
        m_path_root / "pq_chainlock_signer_invalid_schedule"};
    auto invalid_schedule{fixture->schedule};
    ++invalid_schedule.chainlock_period;
    BOOST_REQUIRE(!invalid_schedule.IsValid());
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash,
        invalid_schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::NONE};
    BOOST_CHECK(!signer.Sign(
        *context, 0, 0,
        *fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error).share);
    BOOST_CHECK(error == ChainLockSigningError::INVALID_SCHEDULE);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, fixture->local_pro_tx_hash));
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_prepared_context_before_reservation)
{
    auto fixture{MakeFixture()};
    const auto context{PrepareContext(*fixture)};
    llmq::CPQSignerJournal journal{
        m_path_root / "pq_chainlock_signer_context_mismatch"};
    ChainLockSigningError error{ChainLockSigningError::NONE};

    const uint256 wrong_genesis{NonNullHash(90'001)};
    ChainLockShareSigner wrong_genesis_signer{
        wrong_genesis, fixture->local_pro_tx_hash,
        fixture->schedule, journal};
    BOOST_CHECK(!wrong_genesis_signer.Sign(
        *context, 0, 0, *fixture->child_secret_key,
        fixture->child_key_proof, std::nullopt, &error).share);
    BOOST_CHECK(error == ChainLockSigningError::INVALID_CONTEXT);
    BOOST_CHECK(!journal.GetBranchLock(
        wrong_genesis, fixture->local_pro_tx_hash));

    auto other_schedule{fixture->schedule};
    other_schedule.epoch_origin = 0;
    BOOST_REQUIRE(other_schedule.IsValid());
    ChainLockShareSigner wrong_schedule_signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash,
        other_schedule, journal};
    BOOST_CHECK(!wrong_schedule_signer.Sign(
        *context, 0, 0, *fixture->child_secret_key,
        fixture->child_key_proof, std::nullopt, &error).share);
    BOOST_CHECK(error == ChainLockSigningError::INVALID_CONTEXT);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, fixture->local_pro_tx_hash));
}

BOOST_AUTO_TEST_SUITE_END()
