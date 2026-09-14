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

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <memory>

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

CBlock MakeCommitmentBlock(const llmq::CFinalCommitmentTxPayload& payload)
{
    CMutableTransaction transaction;
    transaction.nVersion = SYSCOIN_TX_VERSION_MN_QUORUM_COMMITMENT;
    SetTxPayload(transaction, payload);

    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(std::move(transaction)));
    return block;
}

CBlock MakeCommitmentBlock(uint32_t height, const uint256& quorum_hash)
{
    llmq::CFinalCommitmentTxPayload payload;
    payload.nHeight = height;
    payload.commitment = llmq::CFinalCommitment{quorum_hash};
    return MakeCommitmentBlock(payload);
}

CDeterministicMNList MakeQuorumSnapshot(const uint256& hash, int height)
{
    const auto size{Params().GetConsensus().legacyQuorumReplay.size};
    CDeterministicMNList list{hash, height, static_cast<uint32_t>(size)};
    for (int i{0}; i < size; ++i) {
        auto member{std::make_shared<CDeterministicMN>(i)};
        member->proTxHash = TestHash(0x10 + i);
        member->collateralOutpoint = COutPoint{TestHash(0x20 + i), 0};
        auto state{std::make_shared<CDeterministicMNState>()};
        state->keyIDOwner.begin()[0] = 0x30 + i;
        state->UpdateConfirmedHash(member->proTxHash, TestHash(0x40 + i));
        member->pdmnState = std::move(state);
        list.AddMN(member, /*fBumpTotalCount=*/false);
    }
    return list;
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
    null_commitment.version = std::numeric_limits<uint16_t>::max();
    BOOST_CHECK(null_commitment.IsStructurallyValid(
        400, 401, 401, llmq::legacy::BASIC_SCHEME_COMMITMENT_VERSION));

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
    // A historical null commitment needs no locally retained quorum snapshot.
    const CBlock carrier_block{
        MakeCommitmentBlock(carrier_height, quorum_hash)};
    BlockValidationState replay_state;
    BOOST_REQUIRE(processor.ProcessBlock(
        carrier_block, &carrier_index, replay_state, decoded,
        /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK(decoded.commitment.IsNull());
    BOOST_CHECK(!decoded.IsNull());

    auto historical_null{decoded};
    historical_null.commitment.nVersion =
        std::numeric_limits<uint16_t>::max();
    BlockValidationState historical_state;
    BOOST_REQUIRE(processor.ProcessBlock(
        MakeCommitmentBlock(historical_null), &carrier_index,
        historical_state, decoded, /*just_check=*/false,
        /*check_sigs=*/false));

    CBlock absent_block;
    absent_block.vtx.emplace_back(MakeTransactionRef(CMutableTransaction{}));
    BlockValidationState absent_state;
    BOOST_REQUIRE(processor.ProcessBlock(
        absent_block, &carrier_index, absent_state, decoded,
        /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK(decoded.IsNull());

    const auto check_invalid = [&](const llmq::CFinalCommitmentTxPayload& payload,
                                   const char* reason) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        BlockValidationState state;
        BOOST_CHECK(!processor.ProcessBlock(
            MakeCommitmentBlock(payload), &carrier_index, state, decoded,
            /*just_check=*/false, /*check_sigs=*/false));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(!state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    };
    auto wrong_height{historical_null};
    ++wrong_height.nHeight;
    check_invalid(wrong_height, "bad-qc-cbtx-height");
    for (const bool truncate_signers : {false, true}) {
        auto truncated{historical_null};
        (truncate_signers ? truncated.commitment.signers
                          : truncated.commitment.validMembers).pop_back();
        check_invalid(truncated, "bad-qc-structure");
    }

    BlockValidationState mismatch_state;
    BOOST_CHECK(!processor.ProcessBlock(
        MakeCommitmentBlock(carrier_height, TestHash(0xd3)), &carrier_index,
        mismatch_state, decoded, /*just_check=*/false, /*check_sigs=*/false));
    BOOST_CHECK_EQUAL(mismatch_state.GetRejectReason(),
                      "bad-qc-block-mismatch");
    BOOST_CHECK(mismatch_state.IsInvalid());

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

BOOST_AUTO_TEST_CASE(block_processor_quorum_snapshot_failures_are_local)
{
    SelectParams(ChainType::REGTEST);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    PQActivationRestorer restore{consensus};
    consensus.nPQActivationHeight = std::numeric_limits<int>::max();
    const int interval{consensus.legacyQuorumReplay.session_interval};
    BOOST_REQUIRE_GT(interval, 1);
    const int quorum_height{
        ((std::max(consensus.nNexusStartBlock, consensus.DIP0003Height) +
          interval - 1) / interval) * interval};
    llmq::CQuorumBlockProcessor processor;
    LOCK(cs_main);

    enum class Fault { MISSING, MALFORMED, WRONG_IDENTITY, DEFERRED_FLUSH };
    uint8_t discriminator{0xe0};
    for (const auto fault : {Fault::MISSING, Fault::MALFORMED,
                             Fault::WRONG_IDENTITY, Fault::DEFERRED_FLUSH}) {
        // Each base hash is cold in the process-wide quorum roster cache.
        const uint256 quorum_hash{TestHash(discriminator++)};
        const uint256 carrier_hash{TestHash(discriminator++)};
        CBlockIndex quorum_index;
        quorum_index.nHeight = quorum_height;
        quorum_index.phashBlock = &quorum_hash;
        CBlockIndex carrier_index;
        carrier_index.nHeight = quorum_height + 1;
        carrier_index.pprev = &quorum_index;
        carrier_index.phashBlock = &carrier_hash;
        const auto snapshot{MakeQuorumSnapshot(quorum_hash, quorum_height)};
        BOOST_REQUIRE_EQUAL(snapshot.CalculateQuorum(
            consensus.legacyQuorumReplay.size, quorum_hash).size(),
            consensus.legacyQuorumReplay.size);

        llmq::CFinalCommitmentTxPayload payload;
        payload.nHeight = carrier_index.nHeight;
        auto& commitment{payload.commitment};
        commitment = llmq::CFinalCommitment{quorum_hash};
        commitment.nVersion = llmq::CFinalCommitment::GetVersion(
            quorum_height >= consensus.nV19StartBlock);
        commitment.signers.assign(consensus.legacyQuorumReplay.size, true);
        commitment.validMembers = commitment.signers;
        BOOST_REQUIRE(commitment.quorumPublicKey.SetBytes(Filled<48>(1)));
        commitment.quorumVvecHash = uint256::ONEV;
        BOOST_REQUIRE(commitment.quorumSig.SetBytes(Filled<96>(2)));
        BOOST_REQUIRE(commitment.membersSig.SetBytes(Filled<96>(3)));
        const auto block{MakeCommitmentBlock(payload)};

        auto& db{*deterministicMNManager->m_evoDb};
        db.WriteCache(quorum_hash, snapshot);
        if (fault == Fault::DEFERRED_FLUSH) {
            db.EraseCache(carrier_hash);
            db.FailNextFlushBatchForTesting();
        } else {
            db.EraseCache(quorum_hash);
            if (fault == Fault::MALFORMED) {
                BOOST_REQUIRE(db.FlushCacheToDisk());
                BOOST_REQUIRE(db.Write(quorum_hash, uint8_t{0}));
            } else if (fault == Fault::WRONG_IDENTITY) {
                auto wrong_snapshot{snapshot};
                wrong_snapshot.SetHeight(quorum_height + 1);
                db.WriteCache(quorum_hash, wrong_snapshot);
            }
        }

        llmq::CFinalCommitmentTxPayload decoded;
        BlockValidationState failed_state;
        BOOST_CHECK(!processor.ProcessBlock(
            block, &carrier_index, failed_state, decoded,
            /*just_check=*/false, /*check_sigs=*/false));
        BOOST_CHECK(failed_state.IsError());
        BOOST_CHECK(!failed_state.IsInvalid());
        BOOST_CHECK_EQUAL(failed_state.GetRejectReason(),
                          "failed-qc-quorum-state");

        db.WriteCache(quorum_hash, snapshot);
        BlockValidationState retry_state;
        BOOST_REQUIRE(processor.ProcessBlock(
            block, &carrier_index, retry_state, decoded,
            /*just_check=*/false, /*check_sigs=*/false));
        BOOST_CHECK(retry_state.IsValid());

        auto malformed{payload};
        malformed.commitment.validMembers.pop_back();
        BlockValidationState malformed_state;
        BOOST_CHECK(!processor.ProcessBlock(
            MakeCommitmentBlock(malformed), &carrier_index, malformed_state,
            decoded, /*just_check=*/false, /*check_sigs=*/false));
        BOOST_CHECK(malformed_state.IsInvalid());
        BOOST_CHECK(!malformed_state.IsError());
        BOOST_CHECK_EQUAL(malformed_state.GetRejectReason(), "bad-qc-structure");
    }
}

BOOST_AUTO_TEST_SUITE_END()
