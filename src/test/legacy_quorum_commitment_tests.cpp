// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <evo/deterministicmns.h>
#include <evo/specialtx.h>
#include <llmq/legacy_quorum_commitment.h>
#include <llmq/quorums_blockprocessor.h>
#include <primitives/block.h>

#include <streams.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>

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
    for (std::size_t i{0}; i < 300; ++i) {
        commitment.signers[i] = true;
        commitment.valid_members[i] = true;
    }
    BOOST_REQUIRE(commitment.quorum_public_key.SetBytes(Filled<48>(1)));
    commitment.quorum_vvec_hash = uint256::TWOV;
    BOOST_REQUIRE(commitment.quorum_signature.SetBytes(Filled<96>(2)));
    BOOST_REQUIRE(commitment.members_signature.SetBytes(Filled<96>(3)));
    return commitment;
}

struct PQActivationRestorer {
    Consensus::Params& params;
    const int height{params.nPQActivationHeight};

    ~PQActivationRestorer()
    {
        params.nPQActivationHeight = height;
    }
};

uint256 TestHash(uint8_t value)
{
    uint256 hash;
    hash.begin()[0] = value;
    return hash;
}

CBlock MakeCommitmentBlock(uint32_t height, const uint256& quorum_hash)
{
    llmq::CFinalCommitmentTxPayload payload;
    payload.nHeight = height;
    payload.commitment = llmq::CFinalCommitment{quorum_hash};

    CMutableTransaction transaction;
    transaction.nVersion = SYSCOIN_TX_VERSION_MN_QUORUM_COMMITMENT;
    SetTxPayload(transaction, payload);

    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(std::move(transaction)));
    return block;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(legacy_quorum_commitment_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(opaque_roundtrip_and_structure)
{
    BOOST_CHECK_EQUAL(
        Params().GetConsensus().legacyQuorumReplay.minimum_size, 300);
    const auto commitment{MakeCommitment()};
    BOOST_CHECK(commitment.IsStructurallyValid(400, 400, 300,
        llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION));

    auto below_minimum{commitment};
    below_minimum.signers[299] = false;
    below_minimum.valid_members[299] = false;
    BOOST_CHECK(!below_minimum.IsStructurallyValid(
        400, 400, 300,
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
        400, 300, 300, llmq::legacy::LEGACY_SCHEME_COMMITMENT_VERSION));

    auto commitment{MakeCommitment()};
    commitment.valid_members[399] = true;
    BOOST_CHECK(!commitment.IsStructurallyValid(
        400, 300, 300, llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION));
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

BOOST_AUTO_TEST_CASE(block_processor_replays_sentinel_until_activation)
{
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    PQActivationRestorer restore{consensus};
    consensus.nPQActivationHeight = std::numeric_limits<int>::max();

    llmq::CQuorumBlockProcessor processor;
    LOCK(cs_main);
    BOOST_REQUIRE_GT(consensus.nNexusStartBlock, 0);

    CMutableTransaction malformed_transaction;
    malformed_transaction.nVersion = SYSCOIN_TX_VERSION_MN_QUORUM_COMMITMENT;
    CBlock malformed_block;
    malformed_block.vtx.emplace_back(
        MakeTransactionRef(std::move(malformed_transaction)));
    const uint256 pre_nexus_hash{TestHash(0xd0)};
    CBlockIndex pre_nexus_index;
    pre_nexus_index.nHeight = consensus.nNexusStartBlock - 1;
    pre_nexus_index.phashBlock = &pre_nexus_hash;
    BlockValidationState pre_nexus_state;
    llmq::CFinalCommitmentTxPayload decoded;
    decoded.nHeight = 1;
    BOOST_REQUIRE(processor.ProcessBlock(
        malformed_block, &pre_nexus_index, pre_nexus_state, decoded,
        /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK(decoded.IsNull());

    const int interval{consensus.legacyQuorumReplay.session_interval};
    BOOST_REQUIRE_GT(interval, 0);
    const int quorum_height{
        ((consensus.nNexusStartBlock + interval - 1) / interval) * interval};
    const int carrier_height{quorum_height + 1};
    const uint256 quorum_hash{TestHash(0xd1)};
    const uint256 carrier_hash{TestHash(0xd2)};
    CBlockIndex quorum_index;
    quorum_index.nHeight = quorum_height;
    quorum_index.phashBlock = &quorum_hash;
    CBlockIndex carrier_index;
    carrier_index.nHeight = carrier_height;
    carrier_index.pprev = &quorum_index;
    carrier_index.phashBlock = &carrier_hash;
    deterministicMNManager->m_evoDb->WriteCache(
        quorum_hash, CDeterministicMNList{quorum_hash, quorum_height, 0});

    const CBlock carrier_block{
        MakeCommitmentBlock(carrier_height, quorum_hash)};
    BlockValidationState replay_state;
    BOOST_REQUIRE(processor.ProcessBlock(
        carrier_block, &carrier_index, replay_state, decoded,
        /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK(decoded.commitment.IsNull());

    BlockValidationState mismatch_state;
    BOOST_CHECK(!processor.ProcessBlock(
        MakeCommitmentBlock(carrier_height, TestHash(0xd3)), &carrier_index,
        mismatch_state, decoded, /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK_EQUAL(mismatch_state.GetRejectReason(),
                      "bad-qc-block-mismatch");

    consensus.nPQActivationHeight = carrier_height + 1;
    BlockValidationState last_legacy_state;
    BOOST_REQUIRE(processor.ProcessBlock(
        carrier_block, &carrier_index, last_legacy_state, decoded,
        /*just_check=*/false, /*check_sigs=*/false));

    const uint256 retired_hash{TestHash(0xd4)};
    CBlockIndex retired_index;
    retired_index.nHeight = carrier_height + 1;
    retired_index.pprev = &carrier_index;
    retired_index.phashBlock = &retired_hash;
    BlockValidationState retired_state;
    BOOST_CHECK(!processor.ProcessBlock(
        MakeCommitmentBlock(retired_index.nHeight, quorum_hash), &retired_index,
        retired_state, decoded, /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK_EQUAL(retired_state.GetRejectReason(), "bad-qc-retired");
}

BOOST_AUTO_TEST_SUITE_END()
