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
    FinalChainLock chainlock;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
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

    for (std::size_t quorum_slot{0}; quorum_slot < ACTIVE_QUORUMS; ++quorum_slot) {
        auto& roster = fixture.rosters[quorum_slot];
        auto& descriptor = roster.descriptor;
        descriptor.epoch = static_cast<uint32_t>(10 + quorum_slot);
        descriptor.base_height = static_cast<int32_t>(500 + 300 * quorum_slot);
        descriptor.base_hash = NonNullHash(9200 + quorum_slot);
        descriptor.snapshot_height = descriptor.base_height - 100;
        descriptor.snapshot_hash = NonNullHash(9300 + quorum_slot);
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

BOOST_AUTO_TEST_CASE(preparation_recomputes_roots_context_and_canonical_mapping)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::INVALID_ARGUMENT};
    auto prepared = PrepareFinalChainLockVerification(
        fixture->genesis_hash, fixture->chainlock, fixture->rosters, &error);
    BOOST_REQUIRE(prepared.has_value());
    BOOST_CHECK(error == ChainLockVerificationError::NONE);
    BOOST_REQUIRE_EQUAL(prepared->checks.size(), FINAL_SIGNATURE_COUNT);

    // The serialized signature order crosses from the last threshold member
    // quorum slot 1/member 0 without an encoded index.
    const auto signature_tag = [](const C11SignatureCheck& check) {
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
    BOOST_CHECK(sphincs_c11::SerializePublicKey(
                    prepared->checks[QUORUM_THRESHOLD].GetPublicKey()) ==
                UniqueChildKey(1, 0));
}

BOOST_AUTO_TEST_CASE(preparation_rejects_root_context_index_and_bitmap_corruption)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};

    {
        auto bad_member_root = MakeVerificationFixture();
        bad_member_root->rosters[0].descriptor.member_root.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_member_root->genesis_hash, bad_member_root->chainlock,
            bad_member_root->rosters, &error));
        BOOST_CHECK(error == ChainLockVerificationError::MEMBER_ROOT_MISMATCH);
    }

    {
        auto bad_child_root = MakeVerificationFixture();
        bad_child_root->rosters[0].descriptor.child_key_root.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_child_root->genesis_hash, bad_child_root->chainlock,
            bad_child_root->rosters, &error));
        BOOST_CHECK(error == ChainLockVerificationError::CHILD_KEY_ROOT_MISMATCH);
    }

    {
        auto bad_context = MakeVerificationFixture();
        bad_context->chainlock.statement.quorum_context_hash.begin()[0] ^= 1;
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_context->genesis_hash, bad_context->chainlock,
            bad_context->rosters, &error));
        BOOST_CHECK(error == ChainLockVerificationError::QUORUM_CONTEXT_MISMATCH);
    }

    {
        auto bad_index = MakeVerificationFixture();
        ClearMember(bad_index->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        SetMember(bad_index->chainlock.signer_bitmaps[0], QUORUM_MIN_VALID);
        BOOST_REQUIRE(bad_index->chainlock.IsStructurallyValid());
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_index->genesis_hash, bad_index->chainlock, bad_index->rosters,
            &error));
        BOOST_CHECK(error == ChainLockVerificationError::INVALID_SIGNER);
    }

    {
        auto bad_bitmap = MakeVerificationFixture();
        ClearMember(bad_bitmap->chainlock.signer_bitmaps[0],
                    QUORUM_THRESHOLD - 1);
        BOOST_CHECK(!PrepareFinalChainLockVerification(
            bad_bitmap->genesis_hash, bad_bitmap->chainlock,
            bad_bitmap->rosters, &error));
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
        bad_sibling->genesis_hash, bad_sibling->chainlock,
        bad_sibling->rosters, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);

    auto bad_public_key = MakeVerificationFixture();
    bad_public_key->chainlock.signatures[0].key_proof.public_key[0] ^= 1;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        bad_public_key->genesis_hash, bad_public_key->chainlock,
        bad_public_key->rosters, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_CHILD_PROOF);
}

BOOST_AUTO_TEST_CASE(preparation_rejects_duplicate_members_and_child_keys)
{
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    auto duplicate_member = MakeVerificationFixture();
    duplicate_member->rosters[0].members.back().pro_tx_hash =
        duplicate_member->rosters[0].members[QUORUM_SIZE - 2].pro_tx_hash;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        duplicate_member->genesis_hash, duplicate_member->chainlock,
        duplicate_member->rosters, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_MEMBER);

    auto duplicate_key = MakeVerificationFixture();
    duplicate_key->rosters[0].members[1]
        .child_root->commitment.tree_id =
        duplicate_key->rosters[0].members[0]
            .child_root->commitment.tree_id;
    BOOST_CHECK(!PrepareFinalChainLockVerification(
        duplicate_key->genesis_hash, duplicate_key->chainlock,
        duplicate_key->rosters, &error));
    BOOST_CHECK(error == ChainLockVerificationError::DUPLICATE_CHILD_KEY);
}

BOOST_AUTO_TEST_CASE(real_signature_check_and_owned_queue_lifecycle)
{
    sphincs_c11::SecretSeed secret_seed;
    sphincs_c11::PublicSeed public_seed;
    sphincs_c11::Message message;
    for (std::size_t i{0}; i < secret_seed.size(); ++i) secret_seed[i] = i;
    for (std::size_t i{0}; i < public_seed.size(); ++i) public_seed[i] = 0xa0 + i;
    for (std::size_t i{0}; i < message.size(); ++i) message[i] = (3 + 7 * i) & 0xff;

    sphincs_c11::PublicKey public_key;
    sphincs_c11::SecretKey secret_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(secret_seed, public_seed, public_key,
                                               secret_key));
    sphincs_c11::Signature signature;
    BOOST_REQUIRE(sphincs_c11::Sign(secret_key, message, signature));

    {
        ChainLockVerifier verifier{/*worker_threads=*/2, /*batch_size=*/1};
        std::vector<C11SignatureCheck> checks;
        checks.emplace_back(public_key, message, signature);
        checks.emplace_back(public_key, message, signature);
        BOOST_CHECK(verifier.VerifyChecks(std::move(checks)));

        auto bad_signature = signature;
        bad_signature[0] ^= 1;
        std::vector<C11SignatureCheck> bad_checks;
        bad_checks.emplace_back(public_key, message, std::move(bad_signature));
        BOOST_CHECK(!verifier.VerifyChecks(std::move(bad_checks)));
    }

    // A zero-worker queue is a supported lifecycle: the calling thread owns
    // all work, and an empty batch is a successful no-op for helper users.
    {
        ChainLockVerifier verifier{/*worker_threads=*/0};
        std::vector<C11SignatureCheck> checks;
        checks.emplace_back(public_key, message, signature);
        BOOST_CHECK(verifier.VerifyChecks(std::move(checks)));
        BOOST_CHECK(verifier.VerifyChecks({}));
    }

    BOOST_CHECK_THROW(
        ChainLockVerifier(static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1),
        std::invalid_argument);
    memory_cleanse(secret_seed.data(), secret_seed.size());
}

BOOST_AUTO_TEST_CASE(full_verifier_reports_bad_signature_after_cheap_checks)
{
    const auto fixture = MakeVerificationFixture();
    ChainLockVerificationError error{ChainLockVerificationError::NONE};
    BOOST_CHECK(!VerifyFinalChainLock(
        fixture->genesis_hash, fixture->chainlock, fixture->rosters,
        /*queue=*/nullptr, &error));
    BOOST_CHECK(error == ChainLockVerificationError::INVALID_SIGNATURE);
}

BOOST_AUTO_TEST_SUITE_END()
