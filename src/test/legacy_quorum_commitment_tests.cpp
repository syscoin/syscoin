// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/legacy_quorum_commitment.h>

#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>

namespace {

template <std::size_t Size>
std::array<uint8_t, Size> Filled(uint8_t first)
{
    std::array<uint8_t, Size> bytes{};
    for (std::size_t i{0}; i < Size; ++i) {
        bytes[i] = static_cast<uint8_t>(first + i);
    }
    return bytes;
}

llmq::legacy::FinalCommitment MakeCommitment()
{
    llmq::legacy::FinalCommitment commitment;
    commitment.version = llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION;
    commitment.quorum_hash = uint256::ONEV;
    commitment.signers.assign(400, false);
    commitment.valid_members.assign(400, false);
    for (std::size_t i{0}; i < 240; ++i) {
        commitment.signers[i] = true;
        commitment.valid_members[i] = true;
    }
    BOOST_REQUIRE(commitment.quorum_public_key.SetBytes(Filled<48>(1)));
    commitment.quorum_vvec_hash = uint256::TWOV;
    BOOST_REQUIRE(commitment.quorum_signature.SetBytes(Filled<96>(2)));
    BOOST_REQUIRE(commitment.members_signature.SetBytes(Filled<96>(3)));
    return commitment;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(legacy_quorum_commitment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(opaque_roundtrip_and_structure)
{
    const auto commitment{MakeCommitment()};
    BOOST_CHECK(commitment.IsStructurallyValid(400, 400, 240,
        llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION));

    CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
    encoded << commitment;
    llmq::legacy::FinalCommitment decoded;
    encoded >> decoded;
    BOOST_CHECK(encoded.empty());
    BOOST_CHECK(decoded == commitment);
}

BOOST_AUTO_TEST_CASE(null_and_out_of_roster_bits)
{
    llmq::legacy::FinalCommitment null_commitment;
    null_commitment.quorum_hash = uint256::ONEV;
    null_commitment.signers.assign(400, false);
    null_commitment.valid_members.assign(400, false);
    BOOST_CHECK(null_commitment.IsNull());
    BOOST_CHECK(null_commitment.IsStructurallyValid(
        400, 300, 240, llmq::legacy::LEGACY_SCHEME_COMMITMENT_VERSION));

    auto commitment{MakeCommitment()};
    commitment.valid_members[399] = true;
    BOOST_CHECK(!commitment.IsStructurallyValid(
        400, 300, 240, llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION));
}

BOOST_AUTO_TEST_CASE(bitset_bound_is_checked_before_resize)
{
    CDataStream encoded{SER_NETWORK, PROTOCOL_VERSION};
    WriteCompactSize(encoded, llmq::legacy::MAX_QUORUM_MEMBERS + 1);
    std::vector<bool> bits;
    auto bounded = Using<llmq::legacy::BoundedDynamicBitSetFormatter<
        llmq::legacy::MAX_QUORUM_MEMBERS>>(bits);
    BOOST_CHECK_THROW(encoded >> bounded, std::ios_base::failure);
    BOOST_CHECK(bits.empty());
}

BOOST_AUTO_TEST_SUITE_END()
