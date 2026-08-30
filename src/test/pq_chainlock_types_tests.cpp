// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_types.h>

#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = value & 0xff;
    hash.begin()[1] = (value >> 8) & 0xff;
    hash.begin()[2] = (value >> 16) & 0xff;
    hash.begin()[3] = (value >> 24) & 0xff;
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

RosterBeaconSeed ReadySeed(uint32_t epoch)
{
    RosterBeaconSeed seed;
    seed.state = RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = BTCCursor{
        1'000 + static_cast<int32_t>(epoch),
        NonNullHash(100 + epoch), NonNullHash(200 + epoch)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(300 + epoch);
    return seed;
}

RosterBeaconWindow ReadyWindow(uint32_t first_epoch)
{
    RosterBeaconWindow window;
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] =
            ReadySeed(first_epoch + static_cast<uint32_t>(slot));
    }
    window.next.epoch =
        first_epoch + static_cast<uint32_t>(ACTIVE_QUORUMS);
    return window;
}

ChainLockStatement ValidStatement()
{
    ChainLockStatement statement;
    statement.height = 1445;
    statement.block_hash = NonNullHash(1);
    statement.previous_chainlock_height = 1440;
    statement.previous_chainlock_hash = NonNullHash(2);
    statement.quorum_context_hash = NonNullHash(3);
    statement.payment_probation_state_hash = NonNullHash(4);
    statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    statement.roster_beacons = ReadyWindow(2);
    statement.roster_authorization_state_hash = NonNullHash(5);
    return statement;
}

FinalChainLock ValidChainLock()
{
    FinalChainLock chainlock;
    chainlock.statement = ValidStatement();
    chainlock.selected_quorum_mask = 0b1011;
    chainlock.signatures.resize(FINAL_SIGNATURE_COUNT);
    SetFirstMembers(chainlock.signer_bitmaps[0], QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[1], QUORUM_THRESHOLD);
    SetFirstMembers(chainlock.signer_bitmaps[3], QUORUM_THRESHOLD);
    for (std::size_t sig{0}; sig < chainlock.signatures.size(); ++sig) {
        chainlock.signatures[sig].key_proof.public_key[0] = 1;
        chainlock.signatures[sig].signature[0] =
            static_cast<uint8_t>(sig);
        chainlock.signatures[sig].signature[1] =
            static_cast<uint8_t>(sig >> 8);
    }
    return chainlock;
}

template <typename T>
T RoundTrip(const T& value)
{
    DataStream stream;
    stream << value;
    T decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    return decoded;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_types_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(records_and_commitment_canonicality)
{
    GlobalKeyRecord global;
    global.key_version = 1;
    global.public_key[0] = 1;
    global.child_key_commitment.generation = 1;
    global.child_key_commitment.tree_id = NonNullHash(2);
    global.child_key_commitment.root = NonNullHash(3);
    global.activated_height = 1440;
    BOOST_CHECK(global.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(global) == global);
    global.profile++;
    BOOST_CHECK(!global.IsStructurallyValid());

    auto commitment = GlobalKeyRecord{}.child_key_commitment;
    commitment.generation = 1;
    commitment.tree_id = NonNullHash(4);
    commitment.root = NonNullHash(5);
    BOOST_REQUIRE(commitment.IsStructurallyValid());
    BOOST_CHECK(commitment.CoversEpoch(0));
    BOOST_CHECK(commitment.CoversEpoch(CHILD_KEY_TREE_LEAF_COUNT - 1));
    BOOST_CHECK(!commitment.CoversEpoch(CHILD_KEY_TREE_LEAF_COUNT));
    commitment.generation = CHILD_KEY_TREE_MAX_GENERATION;
    BOOST_CHECK(commitment.IsStructurallyValid());
    BOOST_CHECK(!CanAdvanceChildKeyTreeGeneration(commitment.generation));
    commitment.generation = CHILD_KEY_TREE_MAX_GENERATION + 1;
    BOOST_CHECK(!commitment.IsStructurallyValid());
    commitment.generation = 1;
    commitment.tree_id.SetNull();
    BOOST_CHECK(!commitment.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(cursor_and_descriptor_structure)
{
    BTCCursor cursor;
    BOOST_CHECK(cursor.IsNull());
    BOOST_CHECK(cursor.IsStructurallyValid());
    cursor.sys_height = 10;
    BOOST_CHECK(!cursor.IsStructurallyValid());
    cursor.sys_hash = NonNullHash(1);
    cursor.btc_hash = NonNullHash(2);
    BOOST_CHECK(cursor.IsStructurallyValid());

    QuorumDescriptor descriptor;
    descriptor.epoch = 5;
    descriptor.base_height = 1440;
    descriptor.base_hash = NonNullHash(3);
    descriptor.snapshot_height = 1152;
    descriptor.snapshot_hash = NonNullHash(4);
    descriptor.member_root = NonNullHash(5);
    descriptor.child_key_root = NonNullHash(6);
    descriptor.roster_beacon_hash = NonNullHash(7);
    SetFirstMembers(descriptor.valid_members, QUORUM_MIN_VALID);
    descriptor.valid_count = QUORUM_MIN_VALID;
    BOOST_CHECK(descriptor.IsStructurallyValid());
    BOOST_CHECK(RoundTrip(descriptor) == descriptor);
    descriptor.valid_count--;
    BOOST_CHECK(!descriptor.IsStructurallyValid());
}

BOOST_AUTO_TEST_CASE(final_chainlock_exact_geometry_and_roundtrip)
{
    FinalChainLock chainlock = ValidChainLock();
    BOOST_REQUIRE(chainlock.IsStructurallyValid());
    BOOST_CHECK(IsSelectedQuorumMask(0b0111));
    BOOST_CHECK(IsSelectedQuorumMask(0b1011));
    BOOST_CHECK(!IsSelectedQuorumMask(0b0011));
    BOOST_CHECK(!IsSelectedQuorumMask(0b1111));
    BOOST_CHECK(!IsSelectedQuorumMask(0b10000111));

    DataStream stream;
    stream << chainlock;
    BOOST_CHECK_EQUAL(stream.size(), FinalChainLockSerializedSize());
    BOOST_CHECK_LT(stream.size(), MAX_CHAINLOCK_SIZE);
    FinalChainLock decoded = ReadFinalChainLock(stream, FinalChainLockSerializedSize());
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(decoded == chainlock);

    const auto first = chainlock.SignatureOffset(0, 0);
    const auto last_first_quorum = chainlock.SignatureOffset(0, QUORUM_THRESHOLD - 1);
    const auto first_second_quorum = chainlock.SignatureOffset(1, 0);
    const auto first_third_quorum = chainlock.SignatureOffset(3, 0);
    BOOST_REQUIRE(first && last_first_quorum && first_second_quorum && first_third_quorum);
    BOOST_CHECK_EQUAL(*first, 0U);
    BOOST_CHECK_EQUAL(*last_first_quorum, QUORUM_THRESHOLD - 1);
    BOOST_CHECK_EQUAL(*first_second_quorum, QUORUM_THRESHOLD);
    BOOST_CHECK_EQUAL(*first_third_quorum, 2 * QUORUM_THRESHOLD);
    BOOST_CHECK(!chainlock.SignatureOffset(2, 0));
    BOOST_CHECK(!chainlock.SignatureOffset(4, 0));
    BOOST_CHECK(!chainlock.SignatureOffset(0, QUORUM_SIZE));
}

BOOST_AUTO_TEST_CASE(final_chainlock_rejects_declared_payload_size)
{
    const FinalChainLock chainlock = ValidChainLock();
    DataStream encoded;
    encoded << chainlock;
    BOOST_CHECK_THROW(ReadFinalChainLock(encoded, FinalChainLock::WIRE_SIZE - 1),
                      std::ios_base::failure);

    DataStream encoded_oversize;
    encoded_oversize << chainlock;
    BOOST_CHECK_THROW(ReadFinalChainLock(encoded_oversize, MAX_CHAINLOCK_SIZE + 1),
                      std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(final_chainlock_rejects_noncanonical_bitmaps)
{
    for (const std::size_t count : {QUORUM_THRESHOLD - 1,
                                    QUORUM_THRESHOLD + 1}) {
        FinalChainLock chainlock = ValidChainLock();
        SetFirstMembers(chainlock.signer_bitmaps[0], count);
        BOOST_CHECK(!chainlock.IsStructurallyValid());
        DataStream stream;
        stream << chainlock;
        FinalChainLock decoded;
        BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
    }

    FinalChainLock nonzero_unselected = ValidChainLock();
    nonzero_unselected.signer_bitmaps[2][0] = 1;
    BOOST_CHECK(!nonzero_unselected.IsStructurallyValid());

    FinalChainLock two_quorums = ValidChainLock();
    two_quorums.selected_quorum_mask = 0b0011;
    SetFirstMembers(two_quorums.signer_bitmaps[3], 0);
    BOOST_CHECK(!two_quorums.IsStructurallyValid());

    FinalChainLock four_quorums = ValidChainLock();
    four_quorums.selected_quorum_mask = 0b1111;
    SetFirstMembers(four_quorums.signer_bitmaps[2], QUORUM_THRESHOLD);
    BOOST_CHECK(!four_quorums.IsStructurallyValid());

    FinalChainLock too_few_signatures = ValidChainLock();
    too_few_signatures.signatures.resize(FINAL_SIGNATURE_COUNT - 1);
    BOOST_CHECK(!too_few_signatures.IsStructurallyValid());
    DataStream too_few_stream;
    BOOST_CHECK_THROW(too_few_stream << too_few_signatures, std::ios_base::failure);

    FinalChainLock too_many_signatures = ValidChainLock();
    too_many_signatures.signatures.resize(FINAL_SIGNATURE_COUNT + 1);
    BOOST_CHECK(!too_many_signatures.IsStructurallyValid());
    DataStream too_many_stream;
    BOOST_CHECK_THROW(too_many_stream << too_many_signatures, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(final_chainlock_rejects_truncated_encoding)
{
    const FinalChainLock chainlock = ValidChainLock();
    DataStream encoded;
    encoded << chainlock;
    BOOST_REQUIRE_EQUAL(encoded.size(), FinalChainLockSerializedSize());

    const std::vector<std::byte> truncated(encoded.begin(), encoded.end() - 1);
    DataStream stream{truncated};
    FinalChainLock decoded;
    BOOST_CHECK_THROW(stream >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(final_chainlock_rejects_wire_signature_count_before_allocation)
{
    FinalChainLock chainlock = ValidChainLock();
    DataStream encoded;
    encoded << chainlock;
    BOOST_REQUIRE_EQUAL(encoded.size(), FinalChainLockSerializedSize());

    constexpr std::size_t SIGNATURE_COUNT_OFFSET{
        FinalChainLock::WIRE_SIZE - sizeof(uint16_t) -
        FINAL_SIGNATURE_COUNT * AuthenticatedChildSignature::WIRE_SIZE};
    const uint16_t too_few{FINAL_SIGNATURE_COUNT - 1};
    encoded[SIGNATURE_COUNT_OFFSET] =
        static_cast<std::byte>(too_few & 0xff);
    encoded[SIGNATURE_COUNT_OFFSET + 1] =
        static_cast<std::byte>(too_few >> 8);
    FinalChainLock decoded;
    BOOST_CHECK_THROW(encoded >> decoded, std::ios_base::failure);

    DataStream encoded_too_many;
    encoded_too_many << chainlock;
    const uint16_t too_many{FINAL_SIGNATURE_COUNT + 1};
    encoded_too_many[SIGNATURE_COUNT_OFFSET] =
        static_cast<std::byte>(too_many & 0xff);
    encoded_too_many[SIGNATURE_COUNT_OFFSET + 1] =
        static_cast<std::byte>(too_many >> 8);
    BOOST_CHECK_THROW(encoded_too_many >> decoded, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(logical_and_witness_ids_are_separated)
{
    const uint256 genesis = NonNullHash(100);
    FinalChainLock first = ValidChainLock();
    FinalChainLock second = first;

    SetFirstMembers(second.signer_bitmaps[0], 0);
    for (std::size_t member{QUORUM_SIZE - QUORUM_THRESHOLD}; member < QUORUM_SIZE; ++member) {
        second.signer_bitmaps[0][member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
    second.signatures[0].signature[0] ^= 1;

    BOOST_REQUIRE(first.IsStructurallyValid());
    BOOST_REQUIRE(second.IsStructurallyValid());
    BOOST_CHECK(first.GetLogicalId(genesis) == second.GetLogicalId(genesis));
    BOOST_CHECK(first.GetWitnessId(genesis) != second.GetWitnessId(genesis));
    BOOST_CHECK(first.GetLogicalId(genesis) != first.GetLogicalId(NonNullHash(101)));
    BOOST_CHECK(first.GetWitnessId(genesis) != first.GetWitnessId(NonNullHash(101)));
}

BOOST_AUTO_TEST_CASE(share_hash_binds_member_epoch_btcc_and_genesis)
{
    const ChainLockStatement statement_template{ValidStatement()};
    ChainLockShareTranscript transcript;
    transcript.height = 1445;
    transcript.block_hash = NonNullHash(1);
    transcript.previous_chainlock_height = 1440;
    transcript.previous_chainlock_hash = NonNullHash(2);
    transcript.quorum_context_hash = NonNullHash(3);
    transcript.quorum_epoch = 5;
    transcript.quorum_base_hash = NonNullHash(4);
    transcript.member_index = 10;
    transcript.member_pro_tx_hash = NonNullHash(5);
    transcript.payment_probation_state_hash = NonNullHash(6);
    transcript.roster_transition =
        statement_template.roster_transition;
    transcript.roster_beacons = statement_template.roster_beacons;
    transcript.roster_authorization_state_hash =
        statement_template.roster_authorization_state_hash;
    BOOST_REQUIRE(transcript.IsStructurallyValid());

    const uint256 genesis = NonNullHash(100);
    const uint256 baseline = GetChainLockShareHash(genesis, transcript);
    auto changed = transcript;
    changed.member_index++;
    BOOST_CHECK(baseline != GetChainLockShareHash(genesis, changed));
    changed = transcript;
    changed.quorum_epoch++;
    BOOST_CHECK(baseline != GetChainLockShareHash(genesis, changed));
    changed = transcript;
    changed.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_CHECK(baseline != GetChainLockShareHash(genesis, changed));
    BOOST_CHECK(!changed.IsStructurallyValid());

    ChainLockStatement statement = ValidStatement();
    statement.accepted_btcc_cursor = {};
    statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_CHECK(!statement.IsStructurallyValid());

    const BTCCursor previous_cursor{
        1430, NonNullHash(201), NonNullHash(202)};
    const BTCCursor advanced_cursor{
        1440, NonNullHash(203), NonNullHash(204)};
    statement = ValidStatement();
    statement.previous_btcc_cursor = previous_cursor;
    statement.accepted_btcc_cursor = previous_cursor;
    BOOST_CHECK(statement.IsStructurallyValid());
    statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_CHECK(!statement.IsStructurallyValid());
    statement.accepted_btcc_cursor = advanced_cursor;
    BOOST_CHECK(statement.IsStructurallyValid());
    statement.previous_btcc_cursor = advanced_cursor;
    statement.accepted_btcc_cursor = previous_cursor;
    BOOST_CHECK(!statement.IsStructurallyValid());
    BOOST_CHECK(baseline != GetChainLockShareHash(NonNullHash(101), transcript));
}

BOOST_AUTO_TEST_SUITE_END()
