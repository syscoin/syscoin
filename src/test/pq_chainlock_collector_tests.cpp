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
    ChainLockStatement statement;
    std::array<FrozenQuorumRoster, ACTIVE_QUORUMS> rosters;
    sphincs_c11::SecretKey member_secret_key;
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

    sphincs_c11::SecretSeed secret_seed{};
    sphincs_c11::PublicSeed public_seed{};
    for (std::size_t i{0}; i < secret_seed.size(); ++i) secret_seed[i] = i + 1;
    for (std::size_t i{0}; i < public_seed.size(); ++i) public_seed[i] = 0xa0 + i;
    sphincs_c11::PublicKey member_public_key;
    BOOST_REQUIRE(sphincs_c11::GenerateKeyPair(
        secret_seed, public_seed, member_public_key,
        fixture->member_secret_key));

    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto& roster{fixture->rosters[slot]};
        auto& descriptor{roster.descriptor};
        descriptor.epoch = static_cast<uint32_t>(20 + slot);
        descriptor.base_height = static_cast<int32_t>(500 + slot * 288);
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
                public_key = sphincs_c11::SerializePublicKey(member_public_key);
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

ChainLockShare SignFirstShare(const CollectorFixture& fixture)
{
    FinalChainLock shell;
    shell.statement = fixture.statement;
    ChainLockShare share;
    share.transcript = BuildChainLockShareTranscript(
        shell, fixture.rosters[0].descriptor, 0,
        fixture.rosters[0].members[0].pro_tx_hash);
    const uint256 share_hash{GetChainLockShareHash(
        fixture.genesis_hash, share.transcript)};
    sphincs_c11::Message message;
    std::copy(share_hash.begin(), share_hash.end(), message.begin());
    BOOST_REQUIRE(sphincs_c11::Sign(
        fixture.member_secret_key, message,
        share.authenticated_signature.signature));
    share.authenticated_signature.key_proof = fixture.member_key_proof;
    return share;
}

FrozenQuorumRostersPtr ShareRosters(const CollectorFixture& fixture)
{
    return std::make_shared<const FrozenQuorumRosters>(fixture.rosters);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_collector_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cloned_signer_cannot_add_quorum_weight)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    ShareCollectionError error{ShareCollectionError::INVALID_ARGUMENT};
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->statement, ShareRosters(*fixture),
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

BOOST_AUTO_TEST_CASE(rejects_wrong_statement_member_and_signature)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->statement, ShareRosters(*fixture))};
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
}

BOOST_AUTO_TEST_CASE(invalid_impersonation_does_not_reserve_signer_slot)
{
    auto fixture{MakeFixture()};
    BOOST_REQUIRE(fixture);
    auto collector{ChainLockCollector::Create(
        fixture->genesis_hash, fixture->statement, ShareRosters(*fixture))};
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
        fixture->genesis_hash, fixture->statement, ShareRosters(*fixture))};
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

BOOST_AUTO_TEST_SUITE_END()
