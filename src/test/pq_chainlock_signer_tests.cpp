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

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

constexpr uint8_t AUTHORIZATION_MASK{0b0111};

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

struct SignerFixture {
    uint256 genesis_hash{NonNullHash(8001)};
    uint256 local_pro_tx_hash{NonNullHash(8003)};
    ChainLockScheduleConfig schedule{.epoch_origin = 1440};
    ChainLockStatement statement;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    sphincs_c11::SecretKey child_secret_key;
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

    sphincs_c11::SecretSeed secret_seed{};
    sphincs_c11::PublicSeed public_seed{};
    for (std::size_t i{0}; i < secret_seed.size(); ++i) secret_seed[i] = i + 11;
    for (std::size_t i{0}; i < public_seed.size(); ++i) public_seed[i] = 0xb0 + i;
    sphincs_c11::PublicKey child_public_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(
        secret_seed, public_seed, child_public_key, fixture->child_secret_key));

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = static_cast<uint32_t>(slot);
        descriptor.base_height = 1440 + static_cast<int32_t>(slot * PQ_EPOCH_BLOCKS);
        descriptor.base_hash = NonNullHash(8200 + slot);
        descriptor.snapshot_height = descriptor.base_height - 288;
        descriptor.snapshot_hash = NonNullHash(8300 + slot);

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
                    ? sphincs_c11::SerializePublicKey(child_public_key)
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_signer_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(signs_after_durable_reservation_and_replays_exact_share)
{
    auto fixture{MakeFixture()};
    llmq::CPQSignerJournal journal{m_path_root / "pq_chainlock_signer_replay"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash, fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::INVALID_ARGUMENT};

    const auto first{signer.Sign(
        fixture->statement, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error)};
    BOOST_REQUIRE(first.share);
    BOOST_CHECK(!first.replayed);
    BOOST_CHECK(error == ChainLockSigningError::NONE);
    ChainLockVerificationError verify_error{ChainLockVerificationError::INVALID_ARGUMENT};
    BOOST_CHECK(VerifyChainLockShare(
        fixture->genesis_hash, *first.share, fixture->rosters,
        AUTHORIZATION_MASK, &verify_error));

    const auto replay{signer.Sign(
        fixture->statement, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        fixture->child_secret_key, fixture->child_key_proof,
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
    llmq::CPQSignerJournal journal{m_path_root / "pq_chainlock_signer_conflict"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash, fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::NONE};
    BOOST_REQUIRE(signer.Sign(
        fixture->statement, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error).share);

    auto competing{fixture->statement};
    competing.block_hash = NonNullHash(8999);
    std::array<QuorumDescriptor, ACTIVE_QUORUMS> descriptors;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    competing.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, competing.height, competing.block_hash, descriptors);
    BOOST_CHECK(!signer.Sign(
        competing, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        fixture->child_secret_key, fixture->child_key_proof,
        journal.GetBranchLock(fixture->genesis_hash,
                              fixture->local_pro_tx_hash),
        &error).share);
    BOOST_CHECK(error == ChainLockSigningError::JOURNAL_CONFLICT);

    sphincs_c11::SecretSeed other_seed{};
    sphincs_c11::PublicSeed other_public_seed{};
    other_seed[0] = 9;
    other_public_seed[0] = 7;
    sphincs_c11::PublicKey other_public_key;
    sphincs_c11::SecretKey other_secret_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(
        other_seed, other_public_seed, other_public_key, other_secret_key));
    auto other_height{fixture->statement};
    other_height.height += PQ_CL_PERIOD;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        descriptors[slot] = fixture->rosters[slot].descriptor;
    }
    other_height.quorum_context_hash = GetQuorumContextHash(
        fixture->genesis_hash, other_height.height, other_height.block_hash, descriptors);
    BOOST_CHECK(!signer.Sign(
        other_height, fixture->rosters, AUTHORIZATION_MASK, 0, 0,
        other_secret_key, fixture->child_key_proof,
        journal.GetBranchLock(fixture->genesis_hash,
                              fixture->local_pro_tx_hash),
        &error).share);
    BOOST_CHECK(error == ChainLockSigningError::SECRET_KEY_MISMATCH);
}

BOOST_AUTO_TEST_CASE(rejects_unauthorized_roster_before_journal_reservation)
{
    auto fixture{MakeFixture()};
    llmq::CPQSignerJournal journal{
        m_path_root / "pq_chainlock_signer_unauthorized"};
    ChainLockShareSigner signer{
        fixture->genesis_hash, fixture->local_pro_tx_hash,
        fixture->schedule, journal};
    ChainLockSigningError error{ChainLockSigningError::NONE};
    BOOST_CHECK(!signer.Sign(
        fixture->statement, fixture->rosters, AUTHORIZATION_MASK, 3, 0,
        fixture->child_secret_key, fixture->child_key_proof,
        std::nullopt, &error).share);
    BOOST_CHECK(error == ChainLockSigningError::INACTIVE_QUORUM);
    BOOST_CHECK(!journal.GetBranchLock(
        fixture->genesis_hash, fixture->local_pro_tx_hash));
}

BOOST_AUTO_TEST_SUITE_END()
