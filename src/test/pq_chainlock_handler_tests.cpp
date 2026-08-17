// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_chainlocks.h>

#include <chain.h>
#include <consensus/params.h>
#include <governance/governanceclasses.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

#include <boost/test/unit_test.hpp>

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

CBlock PaymentAuditCarrierBlock(
    const llmq::pq::PaymentAuditReceipt& receipt)
{
    const llmq::pq::BTCCReceipt btcc;
    DataStream tail;
    tail << PAYMENT_AUDIT_RECEIPT_MAGIC_BYTES << receipt
         << BTCC_RECEIPT_MAGIC_BYTES << btcc;
    const auto bytes{MakeUCharSpan(tail)};
    const std::vector<unsigned char> payload{bytes.begin(), bytes.end()};

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN << payload);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(coinbase)));
    return block;
}

Consensus::Params ValidConsensus()
{
    Consensus::Params consensus;
    consensus.hashGenesisBlock = NonNullHash(1);
    consensus.DIP0003Height = 1;
    consensus.nPQLegacyAnchorHeight = 1000;
    consensus.hashPQLegacyAnchorBlock = NonNullHash(2);
    consensus.hashPQLegacyMNState = NonNullHash(3);
    consensus.hashPQLegacyPQRegistryState = NonNullHash(4);
    consensus.nPQPreparationHeight = 1000;
    consensus.nPQChainLockEpochOrigin = 1440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = 1000;
    consensus.nPQBTCCNEVMInjectionLag = llmq::pq::PQ_BTCC_NEVM_LAG;
    consensus.nPQBTCCReceiptAnchorHeight = 1000;
    consensus.hashPQBTCCReceiptAnchorBlock =
        consensus.hashPQLegacyAnchorBlock;
    return consensus;
}

void SetFirstMembers(llmq::pq::QuorumBitmap& bitmap, std::size_t count)
{
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |=
            static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

llmq::pq::FinalChainLock MakeCatchupChainLock(
    int32_t height, int32_t previous_height,
    const uint256& previous_hash, uint64_t salt)
{
    llmq::pq::FinalChainLock chainlock;
    chainlock.statement.height = height;
    chainlock.statement.block_hash = NonNullHash(10'000 + salt);
    chainlock.statement.previous_chainlock_height = previous_height;
    chainlock.statement.previous_chainlock_hash = previous_hash;
    chainlock.statement.quorum_context_hash = NonNullHash(20'000 + salt);
    chainlock.statement.payment_probation_state_hash = NonNullHash(30'000);
    chainlock.selected_quorum_mask = 0b0111;
    chainlock.signatures.resize(llmq::pq::FINAL_SIGNATURE_COUNT);
    for (auto& authenticated : chainlock.signatures) {
        authenticated.key_proof.public_key[0] = 1;
    }
    for (std::size_t slot{0}; slot < llmq::pq::REQUIRED_QUORUMS; ++slot) {
        SetFirstMembers(chainlock.signer_bitmaps[slot],
                        llmq::pq::QUORUM_THRESHOLD);
    }
    chainlock.signatures.front().signature.front() =
        static_cast<uint8_t>(salt);
    return chainlock;
}

llmq::pq::ChainLockFinalityStoreConfig CatchupStoreConfig()
{
    llmq::pq::ChainLockFinalityStoreConfig config;
    config.chainlock_schedule =
        *llmq::pq::MakeChainLockScheduleConfig(/*epoch_origin=*/0);
    config.btcc_schedule.candidate_origin = 0;
    config.anchor.height = 860;
    config.anchor.block_hash = NonNullHash(860);
    return config;
}

class FullReceiptCatchupContext final
    : public llmq::pq::ChainLockFinalityContext
{
public:
    bool full_receipt_history{false};

    std::optional<llmq::pq::ChainLockCandidateContext> PrepareCandidate(
        const llmq::pq::ChainLockCandidateContextRequest& request)
        const override
    {
        return MakeContext(request);
    }

    std::optional<llmq::pq::ChainLockCandidateContext> RecheckCandidate(
        const llmq::pq::ChainLockCandidateContextRequest& request,
        const llmq::pq::ChainLockCandidateContext& prepared) const override
    {
        const auto current{MakeContext(request)};
        return current == prepared
            ? std::optional<llmq::pq::ChainLockCandidateContext>{current}
            : std::nullopt;
    }

    llmq::pq::AcceptedBranchRelation QueryAcceptedBranch(
        int32_t, const uint256&, int32_t, const uint256&) const override
    {
        return llmq::pq::AcceptedBranchRelation::MATCH;
    }

private:
    llmq::pq::ChainLockCandidateContext MakeContext(
        const llmq::pq::ChainLockCandidateContextRequest& request) const
    {
        return llmq::pq::ChainLockCandidateContext{
            /*block_known=*/true,
            /*scripts_validated=*/true,
            /*special_transactions_validated=*/full_receipt_history,
            /*declared_predecessor_is_ancestor=*/true,
            /*descends_from_local_best=*/true,
            /*btcc_transition_validated=*/true,
            request.statement.height,
            request.statement.block_hash,
            NonNullHash(40'000)};
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_handler_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(deployment_configuration_is_fail_closed)
{
    auto consensus{ValidConsensus()};
    const auto config{llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_CHECK_EQUAL(config->anchor.height, consensus.nPQLegacyAnchorHeight);
    BOOST_CHECK(config->anchor.block_hash == consensus.hashPQLegacyAnchorBlock);
    BOOST_CHECK_EQUAL(config->chainlock_schedule.epoch_origin,
                      consensus.nPQChainLockEpochOrigin);
    BOOST_CHECK_EQUAL(config->btcc_schedule.candidate_origin,
                      consensus.nPQBTCCCandidateOrigin);
    BOOST_CHECK_EQUAL(config->btcc_receipt_assumption_anchor.height, 1000);
    const auto quorum_config{llmq::MakePQQuorumBuildConfig(consensus)};
    BOOST_REQUIRE(quorum_config);
    BOOST_CHECK_EQUAL(quorum_config->registration_cutoff_blocks, 288U);
    BOOST_CHECK_EQUAL(quorum_config->roster_snapshot_lag_blocks, 288U);

    consensus = ValidConsensus();
    consensus.nPQChainLockEpochOrigin = 2880;
    consensus.nPQRegistrationCutoffBlocks = 531;
    consensus.nPQRosterSnapshotLag = 531;
    BOOST_CHECK(llmq::MakePQQuorumBuildConfig(consensus));
    consensus.nPQRegistrationCutoffBlocks = 532;
    consensus.nPQRosterSnapshotLag = 532;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus.hashPQLegacyPQRegistryState.SetNull();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQChainLockEpochOrigin++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQFutureHorizonEpochs = 0;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQRegistrationCutoffBlocks = 144;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCNEVMInjectionLag++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCCandidateOrigin++;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQBTCCReceiptAnchorBlock.SetNull();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 1001;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 1000;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nDefaultAssumeValidHeight = 999;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = 1011;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = 1010;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus.nDefaultAssumeValidHeight = 1000;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 1001;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 1010;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));
}

BOOST_AUTO_TEST_CASE(verification_worker_count_is_bounded)
{
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(0), 0U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(1), 0U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(2), 1U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(8), 7U);
    BOOST_CHECK_EQUAL(llmq::GetPQChainLockVerifierThreads(256), 16U);
}

BOOST_AUTO_TEST_CASE(pruned_response_index_is_usable_only_for_history)
{
    LOCK(cs_main);
    CBlockIndex response;
    response.nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);

    BOOST_CHECK(llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/false));
    BOOST_CHECK(!llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/true));

    response.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
    BOOST_CHECK(llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/true));

    response.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_VALID);
    BOOST_CHECK(!llmq::IsPaymentAuditResponseBlockUsable(
        response, /*require_block_data=*/false));
}

BOOST_AUTO_TEST_CASE(payment_audit_carrier_context_precedes_archive_lookup)
{
    using Status = llmq::PaymentAuditContextStatus;
    const auto chainlock{llmq::pq::MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(chainlock);
    const llmq::pq::PaymentAuditScheduleConfig config{
        *chainlock,
        llmq::pq::BTCCScheduleConfig{.candidate_origin = 865}};
    const auto schedule{
        llmq::pq::BuildPaymentAuditEpochSchedule(config, 3)};
    BOOST_REQUIRE(schedule);

    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = schedule->epoch;
    receipt.seal_height = schedule->seal_height;
    receipt.seal_block_hash = NonNullHash(500);
    receipt.carrier_height = schedule->carrier_start_height;
    receipt.audit_logical_id = NonNullHash(501);
    receipt.audit_witness_id = NonNullHash(502);
    receipt.commitment_hash = NonNullHash(503);
    receipt.result_hash = NonNullHash(504);
    receipt.next_probation_state_hash = NonNullHash(505);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    constexpr std::size_t PATH_CAPACITY{32};
    const auto path_size{static_cast<std::size_t>(
        receipt.carrier_height - receipt.seal_height + 1)};
    BOOST_REQUIRE(path_size <= PATH_CAPACITY);
    std::array<uint256, PATH_CAPACITY> hashes;
    std::array<CBlockIndex, PATH_CAPACITY> indexes;
    for (std::size_t i{0}; i < path_size; ++i) {
        hashes[i] = NonNullHash(600 + i);
        indexes[i].phashBlock = &hashes[i];
        indexes[i].nHeight = receipt.seal_height +
                             static_cast<int32_t>(i);
        if (i != 0) indexes[i].pprev = &indexes[i - 1];
    }
    receipt.seal_block_hash = hashes[0];

    LOCK(cs_main);
    const CBlockIndex& carrier{indexes[path_size - 1]};
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    receipt, carrier, config) == Status::READY);

    auto wrong_height{receipt};
    ++wrong_height.seal_height;
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    wrong_height, carrier, config) == Status::INVALID);
    auto wrong_hash{receipt};
    wrong_hash.seal_block_hash = NonNullHash(700);
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    wrong_hash, carrier, config) == Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditReceiptCarrierContext(
                    receipt, carrier,
                    llmq::pq::PaymentAuditScheduleConfig{}) ==
                Status::LOCAL_ERROR);
}

BOOST_AUTO_TEST_CASE(deferred_payment_audit_receipt_is_exactly_carrier_bound)
{
    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = 4;
    receipt.seal_height = 1'000;
    receipt.seal_block_hash = NonNullHash(801);
    receipt.carrier_height = 1'010;
    receipt.audit_logical_id = NonNullHash(802);
    receipt.audit_witness_id = NonNullHash(803);
    receipt.commitment_hash = NonNullHash(804);
    receipt.result_hash = NonNullHash(805);
    receipt.next_probation_state_hash = NonNullHash(806);
    BOOST_REQUIRE(receipt.IsStructurallyValid());

    CBlock block{PaymentAuditCarrierBlock(receipt)};
    const uint256 parent_hash{NonNullHash(807)};
    block.hashPrevBlock = parent_hash;
    const uint256 carrier_hash{block.GetHash()};
    const uint256 best_hash{NonNullHash(808)};
    const uint256 sibling_hash{NonNullHash(809)};

    LOCK(cs_main);
    CBlockIndex parent;
    parent.phashBlock = &parent_hash;
    parent.nHeight = receipt.carrier_height - 1;
    CBlockIndex carrier;
    carrier.phashBlock = &carrier_hash;
    carrier.pprev = &parent;
    carrier.nHeight = receipt.carrier_height;
    carrier.nTx = 1;
    carrier.nChainTx = 1;
    carrier.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    CBlockIndex best;
    best.phashBlock = &best_hash;
    best.pprev = &carrier;
    best.nHeight = carrier.nHeight + 1;
    best.nTx = 1;
    best.nChainTx = 2;
    best.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    CBlockIndex sibling;
    sibling.phashBlock = &sibling_hash;
    sibling.pprev = &parent;
    sibling.nHeight = carrier.nHeight;
    sibling.nTx = 1;
    sibling.nChainTx = 1;
    sibling.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    const auto exact{llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best)};
    BOOST_REQUIRE(exact);
    BOOST_CHECK(*exact == receipt);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, NonNullHash(900), carrier, best));
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, sibling));

    carrier.nStatus = static_cast<BlockStatus>(
        carrier.nStatus | BLOCK_FAILED_VALID);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
    carrier.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA);
    best.nStatus = static_cast<BlockStatus>(BLOCK_VALID_TRANSACTIONS);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
    best.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA | BLOCK_ASSUMED_VALID);
    BOOST_CHECK(!llmq::ExtractDeferredPaymentAuditReceipt(
        block, receipt.audit_witness_id, carrier, best));
}

BOOST_AUTO_TEST_CASE(payment_audit_context_waits_for_local_validation)
{
    using Status = llmq::PaymentAuditContextStatus;
    using SealValidation = llmq::PaymentAuditSealValidation;

    LOCK(cs_main);
    int32_t last_superblock{0};
    int32_t superblock_height{0};
    CSuperblock::GetNearestSuperblocksHeights(
        /*nBlockHeight=*/0, last_superblock, superblock_height);
    BOOST_REQUIRE_EQUAL(last_superblock, 0);
    BOOST_REQUIRE(superblock_height > 1);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(superblock_height));
    const uint256 predecessor_hash{NonNullHash(100)};
    const uint256 seal_hash{NonNullHash(101)};
    CBlockIndex predecessor;
    predecessor.nHeight = superblock_height - 1;
    predecessor.phashBlock = &predecessor_hash;
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    CBlockIndex seal;
    seal.nHeight = superblock_height;
    seal.phashBlock = &seal_hash;
    seal.pprev = &predecessor;
    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    nullptr, /*expected_height=*/seal.nHeight,
                    predecessor.nHeight, predecessor_hash,
                    SealValidation::LIVE_EXACT) == Status::LOCAL_ERROR);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::READY);

    // Old BTCC-only provenance cannot authenticate the payment-audit and
    // probation roots used by historical audit verification.
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::LOCAL_ERROR);
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::LOCAL_ERROR);
    seal.nStatus = static_cast<BlockStatus>(
        seal.nStatus | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::READY);

    // The predecessor is the authenticated checkpoint and need not carry the
    // new receipt bit. Every later block does, and every superblock in that
    // suffix independently retains exact governance provenance.
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    const uint256 middle_hash{NonNullHash(103)};
    CBlockIndex middle;
    middle.nHeight = predecessor.nHeight + 1;
    middle.phashBlock = &middle_hash;
    middle.pprev = &predecessor;
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    const uint256 target_hash{NonNullHash(104)};
    CBlockIndex target;
    target.nHeight = middle.nHeight + 1;
    target.phashBlock = &target_hash;
    target.pprev = &middle;
    constexpr uint32_t target_ready{
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_PQ_RECEIPT_INDEX_VALIDATED};
    target.nStatus = static_cast<BlockStatus>(target_ready);
    const auto classify_target = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        return llmq::ClassifyPaymentAuditSealContext(
            &target, target.nHeight, predecessor.nHeight,
            predecessor_hash, SealValidation::LIVE_EXACT);
    };
    BOOST_CHECK(classify_target() == Status::READY);

    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        middle.nStatus | BLOCK_GOVERNANCE_VALIDATED);
    target.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    target.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    target.nStatus = static_cast<BlockStatus>(target_ready);
    BOOST_CHECK(classify_target() == Status::READY);

    middle.nStatus = static_cast<BlockStatus>(
        middle.nStatus | BLOCK_ASSUMED_VALID);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        (middle.nStatus & ~BLOCK_ASSUMED_VALID) | BLOCK_FAILED_VALID);
    BOOST_CHECK(classify_target() == Status::LOCAL_ERROR);
    middle.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_GOVERNANCE_VALIDATED);
    predecessor.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight + 1, predecessor.nHeight,
                    predecessor_hash, SealValidation::LIVE_EXACT) ==
                Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, seal.nHeight, seal_hash,
                    SealValidation::LIVE_EXACT) == Status::INVALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    NonNullHash(102), SealValidation::LIVE_EXACT) ==
                Status::INVALID);

    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_ASSUMED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::LOCAL_ERROR);
    seal.nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
        BLOCK_FAILED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditSealContext(
                    &seal, seal.nHeight, predecessor.nHeight,
                    predecessor_hash,
                    SealValidation::THRESHOLD_ATTESTED_HISTORY) ==
                Status::INVALID);

    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    nullptr, /*require_block_data=*/false) ==
                Status::LOCAL_ERROR);
    CBlockIndex response;
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::LOCAL_ERROR);
    response.nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::READY);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/true) ==
                Status::LOCAL_ERROR);
    response.nStatus = static_cast<BlockStatus>(
        response.nStatus | BLOCK_FAILED_VALID);
    BOOST_CHECK(llmq::ClassifyPaymentAuditResponseContext(
                    &response, /*require_block_data=*/false) ==
                Status::INVALID);
}

BOOST_AUTO_TEST_CASE(old_only_catchup_cannot_promote_store_best)
{
    using AuditStatus = llmq::PaymentAuditContextStatus;
    using SealValidation = llmq::PaymentAuditSealValidation;
    using FinalityError = llmq::pq::ChainLockFinalityError;

    const uint256 predecessor_hash{NonNullHash(110)};
    const uint256 seal_hash{NonNullHash(111)};
    CBlockIndex predecessor;
    predecessor.nHeight = 17519;
    predecessor.phashBlock = &predecessor_hash;
    CBlockIndex seal;
    seal.nHeight = 17520;
    seal.phashBlock = &seal_hash;
    seal.pprev = &predecessor;
    {
        LOCK(cs_main);
        predecessor.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        seal.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
    }

    const auto classify_history = [&] {
        LOCK(cs_main);
        return llmq::ClassifyPaymentAuditSealContext(
            &seal, seal.nHeight, predecessor.nHeight, predecessor_hash,
            SealValidation::THRESHOLD_ATTESTED_HISTORY);
    };

    // Legacy 2048 is sufficient for the BTCC recomputation half, but it does
    // not attest the payment-audit and probation state required to promote a
    // historical certificate into durable finality.
    BOOST_REQUIRE(classify_history() == AuditStatus::LOCAL_ERROR);

    FullReceiptCatchupContext context;
    context.full_receipt_history =
        classify_history() == AuditStatus::READY;
    llmq::pq::ChainLockFinalityStore store{
        NonNullHash(112), CatchupStoreConfig(), context};
    const auto candidate{
        MakeCatchupChainLock(885, 880, NonNullHash(880), 113)};
    FinalityError error{FinalityError::NONE};
    BOOST_CHECK(!store.PrepareCatchupCandidate(candidate, &error));
    BOOST_CHECK(error == FinalityError::BLOCK_NOT_FULLY_VALIDATED);
    BOOST_CHECK(!store.GetBest());

    // A locally reconstructed 4096 range unlocks the same catch-up candidate;
    // the finality store still performs its ordinary recheck before promotion.
    {
        LOCK(cs_main);
        seal.nStatus = static_cast<BlockStatus>(
            seal.nStatus | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    }
    BOOST_REQUIRE(classify_history() == AuditStatus::READY);
    context.full_receipt_history = true;
    auto prepared{store.PrepareCatchupCandidate(candidate, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, candidate, /*signatures_valid=*/true,
        [] { return true; }, {}, &error));
    const auto best{store.GetBest()};
    BOOST_REQUIRE(best);
    BOOST_CHECK(*best == candidate);
}

BOOST_AUTO_TEST_CASE(payment_audit_archive_failures_are_not_invalid_certs)
{
    using Status = llmq::CChainLocksHandler::
        PaymentAuditReceiptCertificateStatus;
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/false,
                        /*healthy_before_read=*/false,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/false) ==
                Status::UNAVAILABLE);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/true,
                        /*healthy_before_read=*/true,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/true) ==
                Status::MISSING);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveRead(
                        /*store_available=*/true,
                        /*healthy_before_read=*/true,
                        /*witness_found=*/false,
                        /*healthy_after_read=*/false) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveMutation(
                        llmq::pq::PaymentAuditStoreResult::DATABASE_ERROR) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
                    ClassifyPaymentAuditArchiveMutation(
                        llmq::pq::PaymentAuditStoreResult::INVALID) ==
                Status::LOCAL_ERROR);
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::SNAPSHOT_LOOKUP_FAILED));
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::SNAPSHOT_MISMATCH));
    BOOST_CHECK(llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::MISSING_BRANCH_ANCESTOR));
    BOOST_CHECK(!llmq::CChainLocksHandler::
        IsPaymentAuditLocalRosterBuildError(
            llmq::pq::QuorumBuildError::INVALID_TARGET_HEIGHT));
}

BOOST_AUTO_TEST_CASE(payment_audit_required_history_ingress_survives_kill_switch)
{
    BOOST_CHECK(llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/true, /*local_certificate=*/true,
        /*authorized_remote_response=*/false));
    BOOST_CHECK(llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/false,
        /*authorized_remote_response=*/true));
    BOOST_CHECK(!llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/true,
        /*authorized_remote_response=*/false));
    BOOST_CHECK(!llmq::IsPaymentAuditCertificateIngressAllowed(
        /*operational=*/false, /*local_certificate=*/false,
        /*required_remote_response=*/false));

    using Mode = llmq::PaymentAuditCertificateContextMode;
    BOOST_CHECK(llmq::ClassifyPaymentAuditCertificateContext(
                    /*historical_required=*/true,
                    /*historical_resolved=*/true) == Mode::HISTORICAL);
    BOOST_CHECK(llmq::ClassifyPaymentAuditCertificateContext(
                    /*historical_required=*/true,
                    /*historical_resolved=*/false) == Mode::RETRY);
    BOOST_CHECK(llmq::ClassifyPaymentAuditCertificateContext(
                    /*historical_required=*/false,
                    /*historical_resolved=*/false) == Mode::LIVE);
    BOOST_CHECK(llmq::ClassifyPaymentAuditCertificateContext(
                    /*historical_required=*/false,
                    /*historical_resolved=*/true) == Mode::HISTORICAL);
}

BOOST_AUTO_TEST_CASE(preseal_never_disables_durable_base_finality)
{
    BOOST_CHECK(llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/false));
    BOOST_CHECK(llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/true));
    BOOST_CHECK(!llmq::ShouldEnforceDurableChainLock(
        /*configured=*/true, /*persisted_import_pending=*/true,
        /*btcc_preseal_active=*/true));
    BOOST_CHECK(!llmq::ShouldEnforceDurableChainLock(
        /*configured=*/false, /*persisted_import_pending=*/false,
        /*btcc_preseal_active=*/false));
}

BOOST_AUTO_TEST_CASE(updated_receipt_anchor_routes_exact_target_to_catchup)
{
    constexpr int32_t local_best{1000};
    constexpr int32_t receipt_anchor{1010};
    constexpr int32_t carrier{receipt_anchor +
                              static_cast<int32_t>(
                                  llmq::pq::PQ_BTCC_NEVM_LAG)};
    auto consensus{ValidConsensus()};
    consensus.nPQBTCCReceiptAnchorHeight = receipt_anchor;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(30);
    const auto config{llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_CHECK(llmq::pq::IsBTCCReceiptCarrierHeight(
        config->btcc_schedule, carrier));

    // The first post-anchor carrier C=A+10 may carry the exact ADVANCE T=A.
    // Because A is newer than the local winner S, marker authorization must
    // publish it through CATCHUP rather than the archive-only path.
    BOOST_CHECK(llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/true, receipt_anchor, local_best));
    BOOST_CHECK(!llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/false, receipt_anchor, local_best));
    BOOST_CHECK(!llmq::ShouldRouteBTCCPresealReceiptToCatchup(
        /*marker_authorized_receipt=*/true, receipt_anchor, receipt_anchor));
}

BOOST_AUTO_TEST_CASE(durable_seal_closes_consensus_preseal_without_geth)
{
    // Geth availability is deliberately absent from this predicate. Once a
    // fully verified descendant winner is fsynced on the same branch, signing
    // may resume while the separate replay obligation remains durable.
    BOOST_CHECK(llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1115,
        /*winner_descends_marker=*/true));
    BOOST_CHECK(!llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1095,
        /*winner_descends_marker=*/true));
    BOOST_CHECK(!llmq::IsBTCCPresealCoveredByDurableWinner(
        /*marker_height=*/1100, /*winner_height=*/1115,
        /*winner_descends_marker=*/false));
}

BOOST_AUTO_TEST_CASE(payment_audit_checkpoint_boundary_ignores_authorizer_refresh)
{
    llmq::pq::PaymentAuditStoreCheckpoint checkpoint;
    checkpoint.prune_through_epoch = 7;
    checkpoint.covered_through_height = 100;
    checkpoint.covered_through_hash = NonNullHash(100);
    checkpoint.authenticated_receipt_state.cursor = {
        99, 7, NonNullHash(101), NonNullHash(102), NonNullHash(103)};
    checkpoint.authenticated_receipt_state.cumulative_hash =
        NonNullHash(104);
    checkpoint.authenticated_probation_state_hash = NonNullHash(105);
    checkpoint.authorizing_target_height = 110;
    checkpoint.authorizing_target_hash = NonNullHash(106);
    checkpoint.authorizing_chainlock_logical_id = NonNullHash(107);
    checkpoint.authorizing_chainlock_witness_id = NonNullHash(108);
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    BOOST_CHECK(llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, checkpoint));

    auto refreshed{checkpoint};
    // Authorizer-only changes permit archive reuse. The handler still runs
    // probation-state GC because its durable commit is independent.
    refreshed.authorizing_target_height = 120;
    refreshed.authorizing_target_hash = NonNullHash(109);
    refreshed.authorizing_chainlock_logical_id = NonNullHash(110);
    refreshed.authorizing_chainlock_witness_id = NonNullHash(111);
    BOOST_REQUIRE(refreshed.IsStructurallyValid());
    BOOST_CHECK(llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, refreshed));

    const auto boundary_differs = [&](const auto& mutate) {
        auto changed{refreshed};
        mutate(changed);
        BOOST_REQUIRE(changed.IsStructurallyValid());
        BOOST_CHECK(!llmq::HasSamePaymentAuditCheckpointBoundary(
            checkpoint, changed));
    };
    boundary_differs([](auto& changed) {
        ++changed.prune_through_epoch;
    });
    boundary_differs([](auto& changed) {
        ++changed.covered_through_height;
    });
    boundary_differs([](auto& changed) {
        changed.covered_through_hash = NonNullHash(112);
    });
    boundary_differs([](auto& changed) {
        changed.authenticated_receipt_state.cumulative_hash =
            NonNullHash(113);
    });
    boundary_differs([](auto& changed) {
        changed.authenticated_probation_state_hash = NonNullHash(114);
    });

    auto malformed{refreshed};
    malformed.authorizing_target_hash.SetNull();
    BOOST_CHECK(!llmq::HasSamePaymentAuditCheckpointBoundary(
        checkpoint, malformed));
}

BOOST_AUTO_TEST_CASE(preseal_marker_forces_retained_body_recomputation)
{
    LOCK(::cs_main);
    std::vector<uint256> hashes(6);
    std::vector<CBlockIndex> chain(6);
    for (int height{0}; height < static_cast<int>(chain.size()); ++height) {
        hashes[height] = NonNullHash(100 + height);
        chain[height].nHeight = height;
        chain[height].phashBlock = &hashes[height];
        chain[height].pprev = height == 0 ? nullptr : &chain[height - 1];
    }
    chain.back().nStatus = static_cast<BlockStatus>(
        BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);

    llmq::pq::BTCCPresealState state;
    state.active.emplace();
    state.active->earliest_carrier_height = 2;
    state.active->earliest_carrier_hash = hashes[2];
    state.active->terminal_carrier_height = 4;
    state.active->terminal_carrier_hash = hashes[4];

    // The persisted full-validation bit may authorize pruned ordinary
    // catch-up, but an exact marker branch still selects its retained range.
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(state, chain.back()) ==
                &*state.active);
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(state, chain[3]) ==
                nullptr);

    std::array<uint256, 4> fork_hashes{};
    std::array<CBlockIndex, 4> fork_indices{};
    for (int offset{0}; offset < static_cast<int>(fork_indices.size());
         ++offset) {
        fork_hashes[offset] = NonNullHash(200 + offset);
        fork_indices[offset].nHeight = 2 + offset;
        fork_indices[offset].phashBlock = &fork_hashes[offset];
        fork_indices[offset].pprev =
            offset == 0 ? &chain[1] : &fork_indices[offset - 1];
    }
    BOOST_CHECK(llmq::SelectBTCCPresealRecomputeMarker(
                    state, fork_indices.back()) ==
                nullptr);
}

BOOST_AUTO_TEST_CASE(compatibility_object_contains_no_legacy_signature_state)
{
    llmq::CChainLockSig chainlock;
    BOOST_CHECK(chainlock.IsNull());

    llmq::pq::FinalChainLock pq_chainlock;
    pq_chainlock.statement.height = 864;
    pq_chainlock.statement.block_hash = NonNullHash(10);
    chainlock = std::move(pq_chainlock);
    BOOST_CHECK(!chainlock.IsNull());
    BOOST_CHECK_EQUAL(chainlock.statement.height, 864);
    BOOST_CHECK(chainlock.statement.block_hash == NonNullHash(10));
}

BOOST_AUTO_TEST_CASE(share_relay_identity_is_independent_from_original_signer)
{
    std::array<llmq::pq::FrozenQuorumRoster, llmq::pq::ACTIVE_QUORUMS>
        rosters{};
    auto& roster{rosters[0]};
    roster.descriptor.epoch = 7;
    roster.descriptor.base_hash = NonNullHash(20);

    const uint256 original_signer{NonNullHash(21)};
    const uint256 authenticated_relay{NonNullHash(22)};
    roster.members[3].eligible = true;
    roster.members[3].pro_tx_hash = original_signer;
    roster.members[3].child_root.emplace();
    roster.members[9].eligible = true;
    roster.members[9].pro_tx_hash = authenticated_relay;
    roster.members[9].child_root.emplace();

    llmq::pq::ChainLockShareTranscript transcript;
    transcript.quorum_epoch = roster.descriptor.epoch;
    transcript.quorum_base_hash = roster.descriptor.base_hash;
    transcript.member_index = 3;
    transcript.member_pro_tx_hash = original_signer;

    BOOST_CHECK(original_signer != authenticated_relay);
    BOOST_CHECK(llmq::IsAuthorizedChainLockShareRelay(
        rosters, authenticated_relay, transcript));

    transcript.member_pro_tx_hash = NonNullHash(23);
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, authenticated_relay, transcript));
    transcript.member_pro_tx_hash = original_signer;
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, NonNullHash(24), transcript));
}

BOOST_FIXTURE_TEST_CASE(
    updated_receipt_anchor_is_a_valid_historical_range_boundary,
    RegTestingSetup)
{
    constexpr int32_t receipt_anchor_height{1010};
    constexpr std::size_t range_size{11};
    std::array<uint256, range_size> hashes;
    std::array<CBlockIndex, range_size> indices;
    {
        LOCK(::cs_main);
        for (std::size_t offset{0}; offset < range_size; ++offset) {
            hashes[offset] = NonNullHash(31 + offset);
            indices[offset].nHeight = receipt_anchor_height + offset;
            indices[offset].phashBlock = &hashes[offset];
            indices[offset].pprev =
                offset == 0 ? nullptr : &indices[offset - 1];
            indices[offset].nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        }
    }
    CBlockIndex& candidate{indices.back()};

    llmq::pq::BTCCReceiptAssumptionAnchor anchor;
    anchor.height = receipt_anchor_height;
    anchor.block_hash = hashes.front();

    auto& chainman{
        static_cast<TestChainstateManager&>(*Assert(m_node.chainman))};
    {
        LOCK(::cs_main);
        candidate.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED |
            BLOCK_GOVERNANCE_VALIDATED);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE);
    }
    chainman.JumpOutOfIbd();
    {
        LOCK(::cs_main);
        candidate.nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::VALID);

        for (std::size_t offset{1}; offset < range_size; ++offset) {
            indices[offset].nStatus = static_cast<BlockStatus>(
                BLOCK_VALID_SCRIPTS | BLOCK_PQ_BTCC_INDEX_VALIDATED);
        }
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::VALID);

        indices[5].nStatus = static_cast<BlockStatus>(BLOCK_VALID_SCRIPTS);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_ASSUMED_VALID);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::TRANSIENT_UNAVAILABLE);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED |
            BLOCK_FAILED_VALID);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);
        indices[5].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);

        CBlockIndex below_anchor;
        const uint256 below_hash{NonNullHash(32)};
        below_anchor.nHeight = receipt_anchor_height - 1;
        below_anchor.phashBlock = &below_hash;
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, below_anchor, anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);

        auto wrong_anchor{anchor};
        wrong_anchor.block_hash = NonNullHash(33);
        BOOST_CHECK(
            llmq::GetFullyValidatedBTCCCatchupRangeStatus(
                chainman, candidate, wrong_anchor) ==
            llmq::BTCCCatchupRangeStatus::DEFINITIVE_INVALID);
    }
}

BOOST_AUTO_TEST_SUITE_END()
