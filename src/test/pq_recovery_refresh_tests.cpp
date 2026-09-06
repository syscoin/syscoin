// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_recovery_refresh.h>

#include <arith_uint256.h>
#include <auxpow.h>
#include <chain.h>
#include <chainparams.h>
#include <llmq/pq_roster_beacon.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <iterator>
#include <limits>
#include <vector>

using namespace llmq::pq;

namespace {

struct RecoveryRefreshTestingSetup : BasicTestingSetup {
    RecoveryRefreshTestingSetup() : BasicTestingSetup{ChainType::REGTEST} {}
};

uint256 TestHash(uint64_t value)
{
    return ArithToUint256(arith_uint256{value});
}

RecoveryRefreshConfig RefreshConfig()
{
    return RecoveryRefreshConfig{
        .activation_height = 0,
        .grace_groups = 1,
        .snapshot_lag_blocks = 10,
        .entropy_delay_blocks = 20,
        .carrier_delay_blocks = 10,
        .carrier_min_depth_blocks = 20,
        .snapshot_min_work_blocks = 20,
        .carrier_min_work_blocks = 20,
        .readiness_window_blocks = 20,
    };
}

template <typename T>
std::vector<uint8_t> Encode(const T& value)
{
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << value;
    const auto bytes{MakeUCharSpan(stream)};
    return {bytes.begin(), bytes.end()};
}

uint256 SetValidAuxpow(CBlockHeader& header, const Consensus::Params& consensus,
                      uint32_t merkle_nonce = 0,
                      const std::vector<uint8_t>& coinbase_output_data = {})
{
    header.SetAuxpowVersion(true);
    const auto hash{header.GetHash()};
    std::vector<uint8_t> merged{std::begin(pchMergedMiningHeader), std::end(pchMergedMiningHeader)};
    merged.insert(merged.end(), std::make_reverse_iterator(hash.end()),
                  std::make_reverse_iterator(hash.begin()));
    CDataStream suffix{SER_NETWORK, PROTOCOL_VERSION};
    suffix << uint32_t{1} << merkle_nonce;
    const auto suffix_bytes{MakeUCharSpan(suffix)};
    merged.insert(merged.end(), suffix_bytes.begin(), suffix_bytes.end());
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout.SetNull();
    transaction.vin[0].scriptSig = CScript{} << merged;
    if (!coinbase_output_data.empty()) {
        transaction.vout.emplace_back(0, CScript{} << OP_RETURN << coinbase_output_data);
    }
    const auto coinbase{MakeTransactionRef(transaction)};
    CPureBlockHeader parent;
    parent.nVersion = 1;
    parent.hashMerkleRoot = coinbase->GetHash();
    while (!CheckProofOfWork(parent.GetHash(), header.nBits, consensus)) ++parent.nNonce;
    CDataStream proof{SER_NETWORK, PROTOCOL_VERSION};
    proof << coinbase << uint256{} << std::vector<uint256>{} << int32_t{0}
          << std::vector<uint256>{} << int32_t{0} << parent;
    auto auxpow{std::make_unique<CAuxPow>()};
    proof >> *auxpow;
    header.SetAuxpow(std::move(auxpow));
    return parent.GetHash();
}

struct WorkBranch {
    ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    BTCCScheduleConfig btcc{.candidate_origin = 0};
    RecoveryRefreshConfig config{RefreshConfig()};
    RecoveryRefreshCoordinates coordinates{
        *DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 1)};
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;
    CBlockHeader entropy_header;
    RecoveryRefreshWorkCommitment commitment;

    explicit WorkBranch(const Consensus::Params& consensus, bool harder_snapshot = false)
        : hashes(coordinates.authority_height + 1),
          indices(coordinates.authority_height + 1)
    {
        LOCK(::cs_main);
        for (int32_t height{0}; height <= coordinates.authority_height; ++height) {
            CBlockHeader header;
            header.SetBaseVersion(1, consensus.nAuxpowChainId);
            header.hashPrevBlock = height == 0 ? uint256{} : hashes[height - 1];
            header.hashMerkleRoot = TestHash(height + 1);
            header.nTime = 1'600'000'000 + height;
            header.nBits = harder_snapshot && height == coordinates.snapshot_height
                ? 0x203fffff : 0x207fffff;
            header.nNonce = height;
            if (height == coordinates.entropy_height) {
                const auto parent_hash{SetValidAuxpow(header, consensus)};
                entropy_header = header;
                commitment.group = coordinates.group;
                commitment.entropy_block_hash = header.GetHash();
                commitment.parent_work_hash = parent_hash;
                commitment.proof = Encode(*header.auxpow);
            }
            hashes[height] = header.GetHash();
            auto& index{indices[height]};
            index.nHeight = height;
            index.phashBlock = &hashes[height];
            index.pprev = height == 0 ? nullptr : &indices[height - 1];
            index.nVersion = header.nVersion;
            index.hashMerkleRoot = header.hashMerkleRoot;
            index.nTime = header.nTime;
            index.nBits = header.nBits;
            index.nNonce = header.nNonce;
            index.nStatus = BLOCK_VALID_SCRIPTS;
            index.nChainWork = GetBlockProof(index) +
                (index.pprev ? index.pprev->nChainWork : arith_uint256{});
            index.BuildSkip();
        }
    }

    CBlockIndex& Carrier() { return indices[coordinates.carrier_height]; }
    CBlockIndex& Authority() { return indices[coordinates.authority_height]; }

    std::optional<ValidatedRecoveryRefreshWorkSample> Verify(
        const Consensus::Params& consensus) const
    {
        return VerifyRecoveryRefreshWorkCommitment(chainlock, btcc, config,
            coordinates, indices[coordinates.carrier_height], commitment, consensus);
    }

    void Index(const ValidatedRecoveryRefreshWorkSample& sample)
    {
        auto& carrier{Carrier()};
        carrier.pqRecoveryRefreshGroup = sample.Group();
        carrier.pqRecoveryRefreshEntropyBlockHash = sample.EntropyBlockHash();
        carrier.pqRecoveryRefreshParentWorkHash = sample.ParentWorkHash();
        carrier.pqRecoveryRefreshCommitmentHash = sample.CommitmentHash();
        carrier.pqRecoveryRefreshWorkValidated = true;
    }
};

CBlock CoinbaseBlock(const std::vector<uint8_t>& data)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << 1 << OP_0;
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << data);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(coinbase));
    return block;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_recovery_refresh_tests, RecoveryRefreshTestingSetup)

BOOST_AUTO_TEST_CASE(config_coordinates_activation_and_one_grace_attempt)
{
    const ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    const BTCCScheduleConfig btcc{.candidate_origin = 0};
    const RecoveryRefreshConfig disabled;
    BOOST_CHECK(disabled.IsDisabled());
    BOOST_CHECK(disabled.IsValid(chainlock, btcc));
    BOOST_CHECK(!DeriveRecoveryRefreshCoordinates(chainlock, btcc, disabled, 1));
    auto config{RefreshConfig()};
    BOOST_REQUIRE(config.IsValid(chainlock, btcc));
    const auto coordinates{DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 1)};
    BOOST_REQUIRE(coordinates);
    BOOST_CHECK_EQUAL(coordinates->first_epoch, 4);
    BOOST_CHECK_EQUAL(coordinates->readiness_reference_height, 1122);
    BOOST_CHECK_EQUAL(coordinates->snapshot_height, 1142);
    BOOST_CHECK_EQUAL(coordinates->entropy_height, 1162);
    BOOST_CHECK_EQUAL(coordinates->carrier_height, 1172);
    BOOST_CHECK_EQUAL(coordinates->target_height, 2020);
    BOOST_CHECK_EQUAL(coordinates->authority_height, 2015);
    BOOST_CHECK(RecoveryRefreshCoordinatesForCarrierHeight(
        chainlock, btcc, config, 1172) == coordinates);
    BOOST_CHECK(RecoveryRefreshCoordinatesForSnapshotHeight(
        chainlock, btcc, config, 1142) == coordinates);
    BOOST_CHECK(!RecoveryRefreshCoordinatesForCarrierHeight(chainlock, btcc, config, 1173));
    BOOST_CHECK(!RecoveryRefreshCoordinatesForSnapshotHeight(chainlock, btcc, config, 1143));
    BOOST_CHECK(!DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 0));
    BOOST_CHECK(!DeriveRecoveryRefreshCoordinates(chainlock, btcc, config,
        std::numeric_limits<uint32_t>::max()));
    config.activation_height = coordinates->readiness_reference_height;
    BOOST_CHECK(DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 1));
    ++config.activation_height;
    BOOST_CHECK(!DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 1));
    config = RefreshConfig();
    config.grace_groups = 2;
    BOOST_CHECK(!config.IsValid(chainlock, btcc));
    config = RefreshConfig();
    config.readiness_window_blocks = 4 * PQ_EPOCH_BLOCKS;
    BOOST_CHECK(!config.IsValid(chainlock, btcc));
    config = RefreshConfig();
    config.entropy_delay_blocks = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK(!config.IsValid(chainlock, btcc));
    config = RefreshConfig();
    config.carrier_min_work_blocks = 0;
    BOOST_CHECK(!config.IsValid(chainlock, btcc));

    config = RefreshConfig();
    constexpr int32_t last_receipt{870};
    BOOST_CHECK(FirstStaleRecoveryGroup(chainlock, btcc, last_receipt) == 1);
    BOOST_CHECK(GetRecoveryRefreshMode(chainlock, btcc, config, 2020, last_receipt) ==
                RecoveryRefreshMode::FROZEN_SOURCE);
    const auto refreshed{DeriveRecoveryRefreshCoordinates(chainlock, btcc, config, 2)};
    BOOST_REQUIRE(refreshed);
    BOOST_CHECK(GetRecoveryRefreshMode(chainlock, btcc, config,
        refreshed->target_height, last_receipt) == RecoveryRefreshMode::POW_REFRESHED_SOURCE);
    BOOST_CHECK(!GetRecoveryRefreshMode(chainlock, btcc, config,
        refreshed->target_height + 5, last_receipt));
    config.activation_height = refreshed->readiness_reference_height + 1;
    BOOST_CHECK(!GetRecoveryRefreshMode(chainlock, btcc, config,
        refreshed->target_height, last_receipt));
    BOOST_CHECK(GetRecoveryRefreshMode(chainlock, btcc, disabled,
        refreshed->target_height, last_receipt) == RecoveryRefreshMode::FROZEN_SOURCE);
}

BOOST_AUTO_TEST_CASE(commitment_framing_is_bounded_unique_and_optional)
{
    WorkBranch branch{Params().GetConsensus()};
    const auto encoded{EncodeRecoveryRefreshWorkCommitment(branch.commitment)};
    BOOST_REQUIRE(encoded);
    BOOST_CHECK(DecodeRecoveryRefreshWorkCommitment(*encoded) == branch.commitment);
    auto trailing{*encoded};
    trailing.push_back(0);
    BOOST_CHECK(!DecodeRecoveryRefreshWorkCommitment(trailing));
    trailing = *encoded;
    trailing.pop_back();
    BOOST_CHECK(!DecodeRecoveryRefreshWorkCommitment(trailing));
    auto wrong_version{branch.commitment};
    wrong_version.version = 2;
    BOOST_CHECK(!EncodeRecoveryRefreshWorkCommitment(wrong_version));
    auto oversized{branch.commitment};
    oversized.proof.resize(RECOVERY_REFRESH_MAX_PROOF_BYTES + 1);
    BOOST_CHECK(!EncodeRecoveryRefreshWorkCommitment(oversized));

    std::vector<uint8_t> frame;
    BOOST_REQUIRE(AppendRecoveryRefreshWorkCommitment(frame, branch.commitment));
    std::optional<RecoveryRefreshWorkCommitment> decoded;
    BOOST_CHECK(ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock({1, 2, 3}), decoded));
    BOOST_CHECK(!decoded);
    BOOST_CHECK(ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock(frame), decoded));
    BOOST_CHECK(decoded == branch.commitment);
    BOOST_CHECK(!AppendRecoveryRefreshWorkCommitment(frame, branch.commitment));
    auto duplicate{frame};
    duplicate.insert(duplicate.end(), frame.begin(), frame.end());
    BOOST_CHECK(!ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock(duplicate), decoded));
    auto multiple_outputs{CoinbaseBlock(frame)};
    CMutableTransaction coinbase{*multiple_outputs.vtx[0]};
    coinbase.vout.push_back(coinbase.vout.front());
    multiple_outputs.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(!ExtractRecoveryRefreshWorkCommitment(multiple_outputs, decoded));
    frame.pop_back();
    BOOST_CHECK(!ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock(frame), decoded));
    BOOST_CHECK(!ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock({'p', 'q', 'r', 'w'}), decoded));
    BOOST_CHECK(!decoded);
}

BOOST_AUTO_TEST_CASE(producer_omits_valid_proof_that_collides_with_receipt_tail)
{
    const auto& consensus{Params().GetConsensus()};
    WorkBranch branch{consensus};
    const auto ordinary_commitment{branch.commitment};
    BOOST_REQUIRE(!IsBTCCReceiptCarrierHeight(branch.btcc, branch.coordinates.carrier_height));
    const auto entropy_hash{branch.entropy_header.GetHash()};
    branch.commitment.parent_work_hash = SetValidAuxpow(
        branch.entropy_header, consensus, 0, {'b', 't', 'c', 'r'});
    branch.commitment.proof = Encode(*branch.entropy_header.auxpow);
    BOOST_REQUIRE_EQUAL(branch.entropy_header.GetHash(), entropy_hash);
    BOOST_REQUIRE(CheckProofOfWork(branch.entropy_header.auxpow->getParentBlockHash(),
                                   branch.entropy_header.nBits, consensus));
    BOOST_REQUIRE(branch.entropy_header.auxpow->check(
        entropy_hash, branch.entropy_header.GetChainId(), consensus));
    BOOST_REQUIRE(branch.Verify(consensus));

    const auto payload{EncodeRecoveryRefreshWorkCommitment(branch.commitment)};
    BOOST_REQUIRE(payload);
    std::vector<uint8_t> raw_frame{'p', 'q', 'r', 'w'};
    const auto size{Encode(static_cast<uint32_t>(payload->size()))};
    raw_frame.insert(raw_frame.end(), size.begin(), size.end());
    raw_frame.insert(raw_frame.end(), payload->begin(), payload->end());
    const auto raw_carrier{CoinbaseBlock(raw_frame)};
    std::optional<RecoveryRefreshWorkCommitment> decoded;
    BOOST_REQUIRE(ExtractRecoveryRefreshWorkCommitment(raw_carrier, decoded));
    BOOST_CHECK(decoded == branch.commitment);
    BOOST_REQUIRE(HasBTCCReceiptCommitment(raw_carrier));

    const std::vector<uint8_t> original_extra{1, 2, 3};
    auto extra{original_extra};
    BOOST_CHECK(!AppendRecoveryRefreshWorkCommitment(extra, branch.commitment));
    BOOST_CHECK(extra == original_extra);
    const auto without_sample{CoinbaseBlock(extra)};
    BOOST_CHECK(!HasBTCCReceiptCommitment(without_sample));
    BOOST_CHECK(ExtractRecoveryRefreshWorkCommitment(without_sample, decoded));
    BOOST_CHECK(!decoded);

    BOOST_REQUIRE(AppendRecoveryRefreshWorkCommitment(extra, ordinary_commitment));
    BOOST_CHECK(ExtractRecoveryRefreshWorkCommitment(CoinbaseBlock(extra), decoded));
    BOOST_CHECK(decoded == ordinary_commitment);
}

BOOST_AUTO_TEST_CASE(proof_is_bound_to_f_and_g_not_a_mutable_local_wrapper)
{
    const auto& consensus{Params().GetConsensus()};
    WorkBranch branch{consensus};
    const auto first{branch.Verify(consensus)};
    BOOST_REQUIRE(first);
    BOOST_CHECK_EQUAL(first->EntropyBlockHash(), branch.entropy_header.GetHash());
    BOOST_CHECK_EQUAL(first->CarrierHash(), branch.Carrier().GetBlockHash());
    const auto original{branch.commitment};
    branch.commitment.group++;
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    branch.commitment.entropy_block_hash = TestHash(456);
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    branch.commitment.parent_work_hash = TestHash(789);
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    branch.commitment.proof.push_back(0);
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    const size_t ignored_hash_offset{Encode(branch.entropy_header.auxpow->getCoinbaseTx()).size()};
    BOOST_REQUIRE(ignored_hash_offset < branch.commitment.proof.size());
    branch.commitment.proof[ignored_hash_offset] = 1;
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    branch.commitment.proof[ignored_hash_offset + 32 + 1] = 1;
    BOOST_CHECK(!branch.Verify(consensus));
    branch.commitment = original;
    const auto original_header_hash{branch.entropy_header.GetHash()};
    // This fresh work sample is not required to reproduce F's accepted
    // mutable wrapper or establish a Bitcoin tip / Nexus reference claim.
    const auto replacement_parent_hash{SetValidAuxpow(branch.entropy_header, consensus, 1)};
    BOOST_CHECK(replacement_parent_hash != original.parent_work_hash);
    BOOST_CHECK_EQUAL(branch.entropy_header.GetHash(), original_header_hash);
    BOOST_CHECK(branch.Verify(consensus));
    branch.commitment.parent_work_hash = replacement_parent_hash;
    branch.commitment.proof = Encode(*branch.entropy_header.auxpow);
    const auto replacement{branch.Verify(consensus)};
    BOOST_REQUIRE(replacement);
    BOOST_CHECK(replacement->CommitmentHash() != first->CommitmentHash());
    BOOST_CHECK(GetRecoveryRefreshEntropyHash(consensus.hashGenesisBlock, TestHash(1), *first) !=
                GetRecoveryRefreshEntropyHash(consensus.hashGenesisBlock, TestHash(1), *replacement));
    BOOST_CHECK(!VerifyRecoveryRefreshWorkCommitment(branch.chainlock, branch.btcc, branch.config,
        branch.coordinates, branch.Authority(), original, consensus));
}

BOOST_AUTO_TEST_CASE(work_depth_and_full_validation_provenance_are_both_required)
{
    LOCK(::cs_main);
    const auto& consensus{Params().GetConsensus()};
    WorkBranch branch{consensus};
    const auto sample{branch.Verify(consensus)};
    BOOST_REQUIRE(sample);
    BOOST_CHECK(ValidateRecoveryRefreshWorkDepth(branch.chainlock, branch.btcc,
        branch.config, branch.coordinates, branch.Authority()));
    const auto indexed = [&] {
        return ValidateIndexedRecoveryRefreshWork(branch.chainlock, branch.btcc,
            branch.config, branch.coordinates, branch.Authority());
    };
    BOOST_CHECK(!indexed());
    branch.Index(*sample);
    BOOST_CHECK(indexed());
    auto& carrier{branch.Carrier()};
    carrier.nStatus |= BLOCK_ASSUMED_VALID;
    BOOST_CHECK(!indexed());
    carrier.nStatus &= ~BLOCK_ASSUMED_VALID;
    carrier.nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(!indexed());
    carrier.nStatus = BLOCK_VALID_TRANSACTIONS;
    BOOST_CHECK(!indexed());
    carrier.nStatus = BLOCK_VALID_SCRIPTS;
    carrier.pqRecoveryRefreshGroup++;
    BOOST_CHECK(!indexed());
    branch.Index(*sample);
    carrier.pqRecoveryRefreshEntropyBlockHash = TestHash(555);
    BOOST_CHECK(!indexed());
    branch.Index(*sample);
    auto& entropy{branch.indices[branch.coordinates.entropy_height]};
    const auto entropy_work{entropy.nChainWork};
    entropy.nChainWork = branch.indices[branch.coordinates.snapshot_height].nChainWork + 1;
    BOOST_CHECK(branch.Verify(consensus));
    BOOST_CHECK(!indexed());
    entropy.nChainWork = entropy_work;
    const auto authority_work{branch.Authority().nChainWork};
    branch.Authority().nChainWork = carrier.nChainWork + 1;
    BOOST_CHECK(!indexed());
    branch.Authority().nChainWork = authority_work;
    BOOST_CHECK(indexed());
    const auto seed{GetRecoveryRefreshEntropyHash(consensus.hashGenesisBlock, TestHash(42), *sample)};
    BOOST_REQUIRE(seed);
    const auto modifier{GetRecoveryRefreshRosterModifier(consensus.hashGenesisBlock, *seed, 1, 4)};
    BOOST_REQUIRE(modifier);
    BOOST_CHECK(modifier != GetRecoveryRefreshRosterModifier(consensus.hashGenesisBlock, *seed, 1, 5));
    BOOST_CHECK(!GetRecoveryRefreshRosterModifier(consensus.hashGenesisBlock, *seed, 1, 8));
    BOOST_CHECK(!GetRecoveryRefreshEntropyHash(uint256{}, TestHash(42), *sample));
    BOOST_CHECK(!GetRecoveryRefreshEntropyHash(consensus.hashGenesisBlock, uint256{}, *sample));

    WorkBranch falling_difficulty{consensus, /*harder_snapshot=*/true};
    BOOST_CHECK(falling_difficulty.Verify(consensus));
    BOOST_CHECK(!ValidateRecoveryRefreshWorkDepth(falling_difficulty.chainlock,
        falling_difficulty.btcc, falling_difficulty.config,
        falling_difficulty.coordinates, falling_difficulty.Authority()));
}

BOOST_AUTO_TEST_CASE(index_round_trip_retains_exact_sample_provenance)
{
    WorkBranch branch{Params().GetConsensus()};
    const auto sample{branch.Verify(Params().GetConsensus())};
    BOOST_REQUIRE(sample);
    branch.Index(*sample);
    CDataStream stream{SER_DISK, PROTOCOL_VERSION};
    stream << CDiskBlockIndex{&branch.Carrier()};
    CDiskBlockIndex decoded;
    stream >> decoded;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(decoded.pqRecoveryRefreshWorkValidated);
    BOOST_CHECK_EQUAL(decoded.pqRecoveryRefreshGroup, sample->Group());
    BOOST_CHECK_EQUAL(decoded.pqRecoveryRefreshEntropyBlockHash, sample->EntropyBlockHash());
    BOOST_CHECK_EQUAL(decoded.pqRecoveryRefreshParentWorkHash, sample->ParentWorkHash());
    BOOST_CHECK_EQUAL(decoded.pqRecoveryRefreshCommitmentHash, sample->CommitmentHash());
    CBlockIndex legacy;
    legacy.nHeight = 1;
    stream << CDiskBlockIndex{&legacy};
    CDiskBlockIndex decoded_legacy;
    stream >> decoded_legacy;
    BOOST_CHECK(stream.empty());
    BOOST_CHECK(!decoded_legacy.pqRecoveryRefreshWorkValidated);
    BOOST_CHECK(decoded_legacy.pqRecoveryRefreshEntropyBlockHash.IsNull());
}

BOOST_AUTO_TEST_SUITE_END()
