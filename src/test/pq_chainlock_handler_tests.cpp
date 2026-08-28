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

#include <algorithm>
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

llmq::pq::PaymentAuditReceipt NonNullPaymentAuditReceipt(uint64_t salt)
{
    llmq::pq::PaymentAuditReceipt receipt;
    receipt.has_audit = 1;
    receipt.epoch = static_cast<uint32_t>(100 + salt);
    receipt.seal_height = static_cast<int32_t>(1'000 + salt);
    receipt.seal_block_hash = NonNullHash(10'000 + salt);
    receipt.carrier_height = receipt.seal_height +
                             llmq::pq::PAYMENT_AUDIT_RECEIPT_DELAY;
    receipt.audit_logical_id = NonNullHash(20'000 + salt);
    receipt.audit_witness_id = NonNullHash(30'000 + salt);
    receipt.commitment_hash = NonNullHash(40'000 + salt);
    receipt.result_hash = NonNullHash(50'000 + salt);
    receipt.next_probation_state_hash = NonNullHash(60'000 + salt);
    receipt.online_members[0] = 1;
    BOOST_REQUIRE(receipt.IsStructurallyValid());
    return receipt;
}

llmq::PaymentAuditReceiptCache::Key PaymentAuditReceiptCacheKey(
    uint64_t salt)
{
    return llmq::PaymentAuditReceiptCache::Key{
        NonNullHash(70'000 + salt),
        static_cast<int32_t>(2'000 + salt),
        NonNullHash(80'000 + salt),
        static_cast<int32_t>(2'001 + salt),
        static_cast<uint32_t>(100 + salt),
        1 + salt};
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
    consensus.nPQChainLockAnchorHeight = 2304;
    consensus.hashPQChainLockAnchorBlock = NonNullHash(5);
    consensus.nPQPreparationHeight = 1000;
    consensus.nPQChainLockEpochOrigin = 1440;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQRosterSnapshotLag = 288;
    consensus.nPQBTCCCandidateOrigin = 2310;
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

llmq::pq::FinalPaymentAudit MakePaymentAuditCandidate(
    uint32_t epoch, uint8_t mask, uint64_t salt,
    std::size_t observed_count = llmq::pq::QUORUM_MIN_VALID)
{
    using namespace llmq::pq;
    FinalPaymentAudit audit;
    auto& commitment{audit.statement.commitment};
    const int32_t anchor_height{
        static_cast<int32_t>(10'000 + epoch * 1'000)};
    commitment.seed.epoch = epoch;
    commitment.seed.anchor = PaymentAuditSeedPoint{
        anchor_height, NonNullHash(100 + salt),
        BTCCursor{anchor_height, NonNullHash(200 + salt),
                  NonNullHash(300 + salt)},
        BTCCAdvance::ADVANCE};
    commitment.seed.anchor_btc_height = 800'000;
    commitment.seed.future_btc_height =
        800'000 + PAYMENT_AUDIT_FUTURE_BTC_HEIGHT_DELTA;
    commitment.seed.future_btc_hash = NonNullHash(400 + salt);
    commitment.selected_row = 3;
    commitment.response_height = anchor_height - 30;
    commitment.deadline_height = anchor_height - 10;
    commitment.response_chainlock_logical_id = NonNullHash(500 + salt);
    commitment.response_advance = BTCCAdvance::ADVANCE;
    commitment.seal_height = anchor_height + PAYMENT_AUDIT_SEAL_DELAY;
    commitment.subject_epoch = epoch;
    commitment.subject_quorum_base_hash = NonNullHash(600 + salt);
    commitment.subject_descriptor_hash = NonNullHash(700 + salt);
    SetFirstMembers(commitment.subject_valid_members, QUORUM_SIZE);
    commitment.previous_probation_state_hash = NonNullHash(800 + salt);

    auto& seal{audit.statement.seal_statement};
    seal.height = commitment.seal_height;
    seal.block_hash = NonNullHash(900 + salt);
    seal.previous_chainlock_height = commitment.seal_height - 5;
    seal.previous_chainlock_hash = NonNullHash(1'000 + salt);
    seal.quorum_context_hash = NonNullHash(1'100 + salt);
    seal.payment_probation_state_hash =
        commitment.previous_probation_state_hash;

    audit.selected_quorum_mask = mask;
    audit.report_witnesses.reserve(PAYMENT_AUDIT_SIGNATURE_COUNT);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        if ((mask & (uint8_t{1} << slot)) == 0) continue;
        SetFirstMembers(audit.signer_bitmaps[slot], QUORUM_THRESHOLD);
        for (std::size_t reporter{0}; reporter < QUORUM_THRESHOLD;
             ++reporter) {
            PaymentAuditReportWitness witness;
            SetFirstMembers(witness.observed_members, observed_count);
            witness.authenticated_signature.key_proof.public_key[0] = 1;
            witness.authenticated_signature.signature[0] =
                static_cast<uint8_t>(salt + slot + reporter);
            audit.report_witnesses.push_back(std::move(witness));
        }
    }
    BOOST_REQUIRE(audit.IsStructurallyValid());
    return audit;
}

llmq::pq::PaymentAuditStoreCheckpoint MakePaymentAuditCheckpoint(
    uint32_t epoch, uint64_t salt, int32_t target_height)
{
    using namespace llmq::pq;
    const int32_t covered_height{target_height - 2};
    PaymentAuditReceiptState receipt_state;
    receipt_state.cursor = {
        covered_height - 1,
        epoch,
        NonNullHash(1'200 + salt),
        NonNullHash(1'300 + salt),
        NonNullHash(1'400 + salt)};
    receipt_state.cumulative_hash = NonNullHash(1'500 + salt);
    PaymentAuditStoreCheckpoint checkpoint{
        epoch,
        covered_height,
        NonNullHash(1'600 + salt),
        receipt_state,
        NonNullHash(1'700 + salt),
        target_height,
        NonNullHash(1'800 + salt),
        NonNullHash(1'900 + salt),
        NonNullHash(2'000 + salt)};
    BOOST_REQUIRE(checkpoint.IsStructurallyValid());
    return checkpoint;
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
    config.btcc_schedule.candidate_origin = 870;
    config.anchor.height = 864;
    config.anchor.block_hash = NonNullHash(864);
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
            NonNullHash(40'000),
            std::nullopt};
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_handler_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(share_admission_gate_linearizes_lifecycle_and_health)
{
    llmq::ShareAdmissionGate gate;
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    gate.SetReady(true);
    const uint64_t first_token{gate.Acquire()};
    BOOST_REQUIRE_NE(first_token, 0U);
    BOOST_CHECK(gate.IsCurrent(first_token));

    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    BOOST_CHECK(!gate.IsCurrent(first_token));
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    const uint64_t second_token{gate.Acquire()};
    BOOST_REQUIRE_NE(second_token, 0U);
    BOOST_CHECK_NE(second_token, first_token);

    gate.SetReady(false);
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    gate.SetReady(true);
    const uint64_t restarted_token{gate.Acquire()};
    BOOST_REQUIRE_NE(restarted_token, 0U);
    BOOST_CHECK_NE(restarted_token, second_token);
    BOOST_CHECK(!gate.IsCurrent(second_token));
}

BOOST_AUTO_TEST_CASE(share_admission_gate_terminal_failure_is_sticky)
{
    llmq::ShareAdmissionGate gate;
    gate.SetReady(true);
    const auto stale_enable{gate.Observe()};
    const auto before_failure{gate.Observe()};
    gate.Fail();
    BOOST_CHECK_NE(gate.Observe().state, before_failure.state);
    BOOST_CHECK(gate.IsTerminal());
    BOOST_CHECK(!gate.TryPublishEnabled(stale_enable, true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    const auto closed_failure{gate.Observe()};
    gate.Fail();
    BOOST_CHECK_NE(gate.Observe().state, closed_failure.state);
    gate.SetReady(false);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    gate.SetReady(true);
    BOOST_CHECK(gate.IsTerminal());
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    llmq::ShareAdmissionGate open_gate;
    open_gate.SetReady(true);
    BOOST_CHECK(open_gate.TryPublishEnabled(open_gate.Observe(), true));
    const uint64_t open_token{open_gate.Acquire()};
    BOOST_REQUIRE_NE(open_token, 0U);
    open_gate.Fail();
    open_gate.SetReady(false);
    BOOST_CHECK(open_gate.TryPublishEnabled(open_gate.Observe(), true));
    open_gate.SetReady(true);
    BOOST_CHECK(!open_gate.IsCurrent(open_token));
    BOOST_CHECK_EQUAL(open_gate.Acquire(), 0U);
}

BOOST_AUTO_TEST_CASE(payment_audit_receipt_cache_is_exact_context_bound)
{
    llmq::PaymentAuditReceiptCache cache;
    const auto key{PaymentAuditReceiptCacheKey(1)};
    const auto receipt{NonNullPaymentAuditReceipt(1)};

    const auto published{cache.Publish(key, receipt)};
    BOOST_REQUIRE(published);
    BOOST_CHECK(*published == receipt);
    const auto cached{cache.Get(key)};
    BOOST_REQUIRE(cached);
    BOOST_CHECK(*cached == receipt);

    const auto expect_miss = [&](auto mutate) {
        auto different{key};
        mutate(different);
        BOOST_CHECK(!cache.Get(different));
    };
    expect_miss([](auto& different) {
        different.carrier_parent_hash = NonNullHash(90'001);
    });
    expect_miss([](auto& different) {
        ++different.carrier_parent_height;
    });
    expect_miss([](auto& different) {
        different.parent_probation_state_hash = NonNullHash(90'002);
    });
    expect_miss([](auto& different) { ++different.carrier_height; });
    expect_miss([](auto& different) { ++different.epoch; });
    expect_miss([](auto& different) { ++different.archive_revision; });

    const auto duplicate{cache.Publish(key, receipt)};
    BOOST_REQUIRE(duplicate);
    BOOST_CHECK(*duplicate == receipt);

    auto conflicting{receipt};
    conflicting.result_hash = NonNullHash(90'003);
    BOOST_REQUIRE(conflicting.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, conflicting));
    const auto retained{cache.Get(key)};
    BOOST_REQUIRE(retained);
    BOOST_CHECK(*retained == receipt);

    const auto before_null{cache.StatsForTesting()};
    BOOST_CHECK(!cache.Publish(PaymentAuditReceiptCacheKey(2), {}));
    const auto after_null{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(after_null.entries, before_null.entries);
    BOOST_CHECK_EQUAL(after_null.builds, before_null.builds);
    BOOST_CHECK_EQUAL(after_null.conflicts, before_null.conflicts);

    BOOST_CHECK_EQUAL(after_null.entries, 1U);
    BOOST_CHECK_EQUAL(after_null.hits, 2U);
    BOOST_CHECK_EQUAL(after_null.builds, 3U);
    BOOST_CHECK_EQUAL(after_null.conflicts, 1U);
}

BOOST_AUTO_TEST_CASE(payment_audit_receipt_cache_is_bounded_and_clearable)
{
    llmq::PaymentAuditReceiptCache cache;
    std::array<llmq::PaymentAuditReceiptCache::Key,
               llmq::PaymentAuditReceiptCache::CAPACITY + 1> keys;
    const auto receipt{NonNullPaymentAuditReceipt(3)};
    for (std::size_t index{0}; index < keys.size(); ++index) {
        keys[index] = PaymentAuditReceiptCacheKey(100 + index);
        BOOST_REQUIRE(cache.Publish(keys[index], receipt));
    }

    auto stats{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(stats.entries,
                      llmq::PaymentAuditReceiptCache::CAPACITY);
    BOOST_CHECK_EQUAL(stats.builds, keys.size());
    BOOST_CHECK(!cache.Get(keys.front()));
    BOOST_REQUIRE(cache.Get(keys.back()));

    cache.Clear();
    stats = cache.StatsForTesting();
    BOOST_CHECK_EQUAL(stats.entries, 0U);
    BOOST_CHECK(!cache.Get(keys.back()));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_preserves_order_and_receipt_fields)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_parity"};
    const uint256 genesis_hash{NonNullHash(91'000)};
    constexpr uint32_t epoch{21};
    const auto pinned{MakePaymentAuditCandidate(epoch, 0x0b, 10)};
    const auto late_slot{MakePaymentAuditCandidate(epoch, 0x07, 11)};
    const auto early_slot{MakePaymentAuditCandidate(epoch, 0x0e, 12)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(pinned) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.PinReferencedWitness(
                      epoch, pinned.GetWitnessId(genesis_hash)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(late_slot) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(early_slot) ==
                  PaymentAuditStoreResult::ACCEPTED);

    PaymentAuditCandidateMetadataCache cache;
    const auto compact{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(compact);
    BOOST_CHECK(compact->IsStructurallyValid());
    const auto full{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(full);
    BOOST_CHECK_EQUAL(compact->candidate_revision, full->revision);
    BOOST_REQUIRE_EQUAL(compact->ordered_candidates.size(),
                        full->ordered_candidates.size());

    for (std::size_t index{0};
         index < full->ordered_candidates.size(); ++index) {
        const auto& source{full->ordered_candidates[index]};
        const auto& metadata{compact->ordered_candidates[index]};
        const auto classification{ClassifyPaymentAuditReports(source.audit)};
        BOOST_REQUIRE(classification);
        BOOST_CHECK(metadata.statement == source.audit.statement);
        BOOST_CHECK(metadata.logical_id == source.logical_id);
        BOOST_CHECK(metadata.witness_id == source.witness_id);
        BOOST_CHECK(metadata.commitment_hash ==
                    GetPaymentAuditCommitmentHash(
                        genesis_hash, source.audit.statement.commitment));
        BOOST_CHECK(metadata.result_hash == GetPaymentAuditResultHash(
                        genesis_hash, source.audit, *classification));
        BOOST_CHECK(metadata.online_members ==
                    classification->online_members);

        const int32_t carrier_height{
            source.audit.statement.commitment.seal_height +
            static_cast<int32_t>(PAYMENT_AUDIT_RECEIPT_DELAY)};
        const uint256 next_state_hash{NonNullHash(92'000 + index)};
        const PaymentAuditReceipt direct{
            PAYMENT_AUDIT_RECEIPT_VERSION,
            1,
            epoch,
            source.audit.statement.commitment.seal_height,
            source.audit.statement.seal_statement.block_hash,
            carrier_height,
            source.logical_id,
            source.witness_id,
            GetPaymentAuditCommitmentHash(
                genesis_hash, source.audit.statement.commitment),
            GetPaymentAuditResultHash(
                genesis_hash, source.audit, *classification),
            next_state_hash,
            classification->online_members};
        const PaymentAuditReceipt from_metadata{
            PAYMENT_AUDIT_RECEIPT_VERSION,
            1,
            epoch,
            metadata.statement.commitment.seal_height,
            metadata.statement.seal_statement.block_hash,
            carrier_height,
            metadata.logical_id,
            metadata.witness_id,
            metadata.commitment_hash,
            metadata.result_hash,
            next_state_hash,
            metadata.online_members};
        BOOST_REQUIRE(direct.IsStructurallyValid());
        BOOST_REQUIRE(from_metadata.IsStructurallyValid());
        BOOST_CHECK(from_metadata == direct);
    }

    const auto repeated{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated);
    BOOST_CHECK(repeated == compact);
    auto stats{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(stats.builds, 1U);
    BOOST_CHECK_EQUAL(stats.hits, 1U);

    const auto empty{cache.GetOrBuild(store, genesis_hash, epoch + 1)};
    BOOST_REQUIRE(empty);
    BOOST_CHECK(empty->IsStructurallyValid());
    BOOST_CHECK(empty->ordered_candidates.empty());
    const auto repeated_empty{
        cache.GetOrBuild(store, genesis_hash, epoch + 1)};
    BOOST_REQUIRE(repeated_empty);
    BOOST_CHECK(repeated_empty == empty);
    stats = cache.StatsForTesting();
    BOOST_CHECK_EQUAL(stats.builds, 2U);
    BOOST_CHECK_EQUAL(stats.hits, 2U);
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_tracks_archive_revision_and_health)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_revision"};
    const uint256 genesis_hash{NonNullHash(93'000)};
    constexpr uint32_t epoch{22};
    const auto first{MakePaymentAuditCandidate(epoch, 0x07, 20)};
    const auto second{MakePaymentAuditCandidate(epoch, 0x0b, 21)};

    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(first) ==
                  PaymentAuditStoreResult::ACCEPTED);
    PaymentAuditCandidateMetadataCache cache;
    const auto initial{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(initial);
    BOOST_REQUIRE_EQUAL(initial->ordered_candidates.size(), 1U);
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        initial->candidate_revision));

    BOOST_REQUIRE(store.AcceptVerified(second) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        initial->candidate_revision));
    const auto advanced{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(advanced);
    BOOST_CHECK_NE(advanced->candidate_revision,
                   initial->candidate_revision);
    BOOST_REQUIRE_EQUAL(advanced->ordered_candidates.size(), 2U);

    const uint256 second_id{second.GetWitnessId(genesis_hash)};
    BOOST_REQUIRE(store.PinReferencedWitness(epoch, second_id) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        advanced->candidate_revision));
    const auto pinned{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(pinned);
    BOOST_REQUIRE_EQUAL(pinned->ordered_candidates.size(), 1U);
    BOOST_CHECK(pinned->ordered_candidates.front().witness_id == second_id);

    BOOST_REQUIRE(store.PruneThroughCheckpoint(
        MakePaymentAuditCheckpoint(epoch, 22, 100'000)));
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        pinned->candidate_revision));
    const auto pruned{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(pruned);
    BOOST_CHECK(pruned->ordered_candidates.empty());
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        pruned->candidate_revision));
    const auto repeated{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated);
    BOOST_CHECK(repeated == pruned);

    const auto before_failures{cache.StatsForTesting()};
    BOOST_CHECK(!cache.GetOrBuild(store, uint256{}, epoch));
    BOOST_CHECK(!cache.GetOrBuild(store, uint256{}, epoch));
    const auto after_failures{cache.StatsForTesting()};
    BOOST_CHECK_EQUAL(after_failures.entries, before_failures.entries);
    BOOST_CHECK_EQUAL(after_failures.builds, before_failures.builds);

    PaymentAuditStore unhealthy{
        m_path_root / "pq_payment_audit_candidate_metadata_unhealthy",
        uint256{}};
    BOOST_CHECK(!unhealthy.IsHealthy());
    BOOST_CHECK(!cache.GetOrBuild(unhealthy, genesis_hash, epoch));
    BOOST_CHECK_EQUAL(cache.StatsForTesting().builds,
                      before_failures.builds);
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_exact_compatibility_fences_stale_negative)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_compatibility"};
    const uint256 genesis_hash{NonNullHash(93'500)};
    constexpr uint32_t epoch{24};
    const auto completed{MakePaymentAuditCandidate(epoch, 0x07, 25)};
    const auto incompatible{MakePaymentAuditCandidate(epoch, 0x0b, 26)};

    PaymentAuditStore store{path, genesis_hash};
    PaymentAuditCandidateMetadataCache cache;
    const auto healthy_empty{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(healthy_empty);
    BOOST_CHECK(healthy_empty->ordered_candidates.empty());
    BOOST_CHECK(!healthy_empty->ContainsExactStatement(
        completed.statement));
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        healthy_empty->candidate_revision));

    const auto repeated_empty{
        cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(repeated_empty);
    BOOST_CHECK(repeated_empty == healthy_empty);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().builds, 1U);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().hits, 1U);

    // A negative decision is usable only while its exact archive revision is
    // still current. Installing the matching witness invalidates it before a
    // runtime can be retained or published.
    BOOST_REQUIRE(store.AcceptVerified(completed) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_CHECK(!store.IsCandidateRevisionCurrent(
        healthy_empty->candidate_revision));
    BOOST_CHECK(!healthy_empty->ContainsExactStatement(
        completed.statement));

    const auto refreshed{cache.GetOrBuild(store, genesis_hash, epoch)};
    BOOST_REQUIRE(refreshed);
    BOOST_CHECK_NE(refreshed->candidate_revision,
                   healthy_empty->candidate_revision);
    BOOST_CHECK(refreshed->ContainsExactStatement(completed.statement));
    BOOST_CHECK(!refreshed->ContainsExactStatement(incompatible.statement));
    BOOST_CHECK(store.IsCandidateRevisionCurrent(
        refreshed->candidate_revision));

    const auto full{store.GetEpochCandidateSnapshot(epoch)};
    BOOST_REQUIRE(full);
    const auto matches_full = [&](const PaymentAuditStatement& statement) {
        return std::any_of(
            full->ordered_candidates.begin(),
            full->ordered_candidates.end(),
            [&](const auto& candidate) {
                return IsPaymentAuditCandidateCompatible(
                    candidate.audit, statement);
            });
    };
    BOOST_CHECK_EQUAL(
        refreshed->ContainsExactStatement(completed.statement),
        matches_full(completed.statement));
    BOOST_CHECK_EQUAL(
        refreshed->ContainsExactStatement(incompatible.statement),
        matches_full(incompatible.statement));

    PaymentAuditStatement invalid_statement;
    BOOST_CHECK(!refreshed->ContainsExactStatement(invalid_statement));
}

BOOST_AUTO_TEST_CASE(
    payment_audit_candidate_metadata_cache_is_exact_bounded_and_clearable)
{
    using namespace llmq;
    using namespace llmq::pq;
    const fs::path path{m_path_root /
                        "pq_payment_audit_candidate_metadata_conflict"};
    const uint256 genesis_hash{NonNullHash(94'000)};
    constexpr uint32_t epoch{23};
    PaymentAuditStore store{path, genesis_hash};
    BOOST_REQUIRE(store.AcceptVerified(
                      MakePaymentAuditCandidate(epoch, 0x07, 30)) ==
                  PaymentAuditStoreResult::ACCEPTED);
    BOOST_REQUIRE(store.AcceptVerified(
                      MakePaymentAuditCandidate(epoch, 0x0b, 31)) ==
                  PaymentAuditStoreResult::ACCEPTED);

    PaymentAuditCandidateMetadataCache source_cache;
    const auto source{source_cache.GetOrBuild(
        store, genesis_hash, epoch)};
    BOOST_REQUIRE(source);
    const PaymentAuditCandidateMetadataCache::Key key{
        epoch, source->candidate_revision};

    auto duplicate_logical_ids{*source};
    duplicate_logical_ids.ordered_candidates[1].logical_id =
        duplicate_logical_ids.ordered_candidates[0].logical_id;
    BOOST_CHECK(duplicate_logical_ids.IsStructurallyValid());
    auto duplicate_witness_ids{duplicate_logical_ids};
    duplicate_witness_ids.ordered_candidates[1].witness_id =
        duplicate_witness_ids.ordered_candidates[0].witness_id;
    BOOST_CHECK(!duplicate_witness_ids.IsStructurallyValid());
    auto invalid_online_subset{*source};
    invalid_online_subset.ordered_candidates[0]
        .statement.commitment.subject_valid_members[0] &=
        static_cast<uint8_t>(~uint8_t{1});
    BOOST_CHECK(!invalid_online_subset.IsStructurallyValid());

    PaymentAuditCandidateMetadataCache cache;
    const auto published{cache.Publish(key, *source)};
    BOOST_REQUIRE(published);
    BOOST_CHECK(cache.Get(key) == published);
    BOOST_CHECK(!cache.Get({epoch + 1, key.candidate_revision}));
    BOOST_CHECK(!cache.Get({epoch, key.candidate_revision + 1}));

    auto reordered{*source};
    std::reverse(reordered.ordered_candidates.begin(),
                 reordered.ordered_candidates.end());
    BOOST_REQUIRE(reordered.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, std::move(reordered)));
    BOOST_CHECK(cache.Get(key) == published);

    auto changed_statement{*source};
    changed_statement.ordered_candidates.front()
        .statement.commitment.seed.future_btc_hash = NonNullHash(95'000);
    BOOST_REQUIRE(changed_statement.IsStructurallyValid());
    BOOST_CHECK(!cache.Publish(key, std::move(changed_statement)));
    BOOST_CHECK(cache.Get(key) == published);
    BOOST_CHECK_EQUAL(cache.StatsForTesting().conflicts, 2U);

    PaymentAuditCandidateMetadataSnapshot invalid;
    BOOST_CHECK(!cache.Publish({}, std::move(invalid)));
    const auto before_fill{cache.StatsForTesting()};

    std::array<PaymentAuditCandidateMetadataCache::Key,
               PaymentAuditCandidateMetadataCache::CAPACITY + 1> keys;
    PaymentAuditCandidateMetadataSnapshotPtr held;
    for (std::size_t index{0}; index < keys.size(); ++index) {
        keys[index] = {epoch + 1,
                       static_cast<uint64_t>(1'000 + index)};
        auto value{cache.Publish(
            keys[index],
            PaymentAuditCandidateMetadataSnapshot{
                keys[index].candidate_revision,
                keys[index].epoch,
                {}})};
        BOOST_REQUIRE(value);
        if (index == 0) held = std::move(value);
    }
    BOOST_REQUIRE(held);
    BOOST_CHECK(held->ordered_candidates.empty());
    BOOST_CHECK_EQUAL(cache.StatsForTesting().entries,
                      PaymentAuditCandidateMetadataCache::CAPACITY);
    BOOST_CHECK(!cache.Get(key));
    BOOST_CHECK(cache.Get(keys.back()));

    cache.Clear();
    BOOST_CHECK_EQUAL(cache.StatsForTesting().entries, 0U);
    BOOST_CHECK(!cache.Get(keys.back()));
    BOOST_CHECK(held->IsStructurallyValid());
    BOOST_CHECK_EQUAL(before_fill.conflicts, 2U);
}

BOOST_AUTO_TEST_CASE(share_admission_gate_rejects_competing_observations)
{
    llmq::ShareAdmissionGate gate;
    gate.SetReady(true);
    const auto stale_enable{gate.Observe()};
    const auto newer_disable{stale_enable};
    BOOST_CHECK(gate.TryPublishEnabled(newer_disable, false));
    BOOST_CHECK(!gate.TryPublishEnabled(stale_enable, true));
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);

    const auto enable{gate.Observe()};
    const auto stale_disable{enable};
    BOOST_CHECK(gate.TryPublishEnabled(enable, true));
    const uint64_t token{gate.Acquire()};
    BOOST_REQUIRE_NE(token, 0U);
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), true));
    BOOST_CHECK_EQUAL(gate.Acquire(), token);
    BOOST_CHECK(!gate.TryPublishEnabled(stale_disable, false));
    BOOST_CHECK(gate.IsCurrent(token));
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK(!gate.IsCurrent(token));

    gate.SetReady(false);
    const auto stopped_enable{gate.Observe()};
    BOOST_CHECK(gate.TryPublishEnabled(gate.Observe(), false));
    BOOST_CHECK(!gate.TryPublishEnabled(stopped_enable, true));
    gate.SetReady(true);
    BOOST_CHECK_EQUAL(gate.Acquire(), 0U);
}

BOOST_AUTO_TEST_CASE(startup_slot_consumption_is_limited_to_live_rounds)
{
    const llmq::pq::ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    BOOST_REQUIRE(chainlock.IsValid());
    BOOST_CHECK(llmq::ShouldConsumeChainLockStartupSlot(
        chainlock, /*startup_tip_height=*/885, /*target_height=*/880));
    BOOST_CHECK(!llmq::ShouldConsumeChainLockStartupSlot(
        chainlock, /*startup_tip_height=*/885, /*target_height=*/885));
}

BOOST_AUTO_TEST_CASE(payment_audit_signing_height_is_exactly_window_bounded)
{
    const llmq::pq::ChainLockScheduleConfig chainlock{.epoch_origin = 0};
    BOOST_REQUIRE(chainlock.IsValid());
    const llmq::pq::PaymentAuditScheduleConfig audit{
        chainlock,
        llmq::pq::BTCCScheduleConfig{.candidate_origin = 865},
    };
    BOOST_REQUIRE(audit.IsValid());
    const auto round{llmq::pq::BuildPaymentAuditEpochSchedule(
        audit, /*epoch=*/3)};
    BOOST_REQUIRE(round);
    const auto first_signing{llmq::pq::SigningHeightForTarget(
        chainlock, round->seal_height)};
    BOOST_REQUIRE(first_signing);
    BOOST_CHECK(!llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, *first_signing - 1));
    BOOST_CHECK(llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, *first_signing));
    BOOST_CHECK(llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, round->carrier_end_height_exclusive - 1));
    BOOST_CHECK(!llmq::IsPaymentAuditSigningHeightLive(
        audit, 3, round->carrier_end_height_exclusive));
    BOOST_CHECK(!llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, *first_signing - 1));
    BOOST_CHECK(llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, *first_signing));
    // SYSCOIN: A deep reorg can revive an old carrier window, so a startup
    // floor beyond that window must still retire an absent old leaf.
    BOOST_CHECK(llmq::ShouldConsumePaymentAuditStartupSlot(
        audit, 3, round->carrier_end_height_exclusive));
}

BOOST_AUTO_TEST_CASE(deployment_configuration_is_fail_closed)
{
    auto consensus{ValidConsensus()};
    const auto config{llmq::MakePQChainLockFinalityStoreConfig(consensus)};
    BOOST_REQUIRE(config);
    BOOST_CHECK_EQUAL(config->anchor.height,
                      consensus.nPQChainLockAnchorHeight);
    BOOST_CHECK(config->anchor.block_hash ==
                consensus.hashPQChainLockAnchorBlock);
    BOOST_CHECK_EQUAL(config->chainlock_schedule.epoch_origin,
                      consensus.nPQChainLockEpochOrigin);
    BOOST_CHECK_EQUAL(config->btcc_schedule.candidate_origin,
                      consensus.nPQBTCCCandidateOrigin);
    BOOST_CHECK_EQUAL(config->btcc_receipt_assumption_anchor.height, 1000);
    const auto first_target{llmq::pq::NextEligibleChainLockTargetHeight(
        config->chainlock_schedule, config->anchor.height)};
    BOOST_REQUIRE(first_target);
    BOOST_CHECK_EQUAL(*first_target, 2305);
    BOOST_CHECK_EQUAL(
        *llmq::pq::SigningHeightForTarget(
            config->chainlock_schedule, *first_target),
        2310);
    const auto quorum_config{llmq::MakePQQuorumBuildConfig(consensus)};
    BOOST_REQUIRE(quorum_config);
    BOOST_CHECK_EQUAL(quorum_config->registration_cutoff_blocks, 288U);
    BOOST_CHECK_EQUAL(quorum_config->roster_snapshot_lag_blocks, 288U);

    consensus = ValidConsensus();
    consensus.nPQChainLockEpochOrigin = 2880;
    consensus.nPQRegistrationCutoffBlocks = 288;
    consensus.nPQRosterSnapshotLag = 288;
    BOOST_CHECK(llmq::MakePQQuorumBuildConfig(consensus));
    consensus.nPQRegistrationCutoffBlocks = 289;
    consensus.nPQRosterSnapshotLag = 289;
    BOOST_CHECK(!llmq::MakePQQuorumBuildConfig(consensus));

    consensus.hashPQLegacyPQRegistryState.SetNull();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.hashPQChainLockAnchorBlock.SetNull();
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQChainLockAnchorHeight--;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQChainLockAnchorHeight =
        consensus.nPQBTCCCandidateOrigin;
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
    consensus.nPQBTCCReceiptAnchorHeight = 2321;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus = ValidConsensus();
    consensus.nPQBTCCReceiptAnchorHeight = 2320;
    consensus.hashPQBTCCReceiptAnchorBlock = NonNullHash(5);
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));

    consensus.nDefaultAssumeValidHeight = 1000;
    BOOST_CHECK(llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 1001;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));
    consensus.nDefaultAssumeValidHeight = 2320;
    BOOST_CHECK(!llmq::MakePQChainLockFinalityStoreConfig(consensus));
}

BOOST_AUTO_TEST_CASE(live_chainlock_candidates_are_current_and_one_window_bound)
{
    const auto schedule{
        llmq::pq::MakeChainLockScheduleConfig(/*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);

    std::array<CBlockIndex, 21> active;
    std::array<uint256, 21> active_hashes;
    for (std::size_t offset{0}; offset < active.size(); ++offset) {
        active_hashes[offset] = NonNullHash(50'000 + offset);
        active[offset].nHeight = 870 + static_cast<int32_t>(offset);
        active[offset].phashBlock = &active_hashes[offset];
        active[offset].pprev = offset == 0 ? nullptr : &active[offset - 1];
    }

    std::array<CBlockIndex, 5> shallow_fork;
    std::array<uint256, 5> shallow_hashes;
    for (std::size_t offset{0}; offset < shallow_fork.size(); ++offset) {
        shallow_hashes[offset] = NonNullHash(51'000 + offset);
        shallow_fork[offset].nHeight = 871 + static_cast<int32_t>(offset);
        shallow_fork[offset].phashBlock = &shallow_hashes[offset];
        shallow_fork[offset].pprev =
            offset == 0 ? &active[0] : &shallow_fork[offset - 1];
    }

    // At tip 880, target 875 is the current signable round. A competing
    // target that shares its height-870 boundary remains admissible.
    BOOST_CHECK(llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[10], shallow_fork.back()));

    // Advancing one round makes the same certificate stale even though its
    // target is now an ancestor of one known branch.
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], shallow_fork.back()));
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], active[5]));
    BOOST_CHECK(llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[15], active[10]));

    std::array<CBlockIndex, 6> deep_fork;
    std::array<uint256, 6> deep_hashes;
    for (std::size_t offset{0}; offset < deep_fork.size(); ++offset) {
        deep_hashes[offset] = NonNullHash(52'000 + offset);
        deep_fork[offset].nHeight = 870 + static_cast<int32_t>(offset);
        deep_fork[offset].phashBlock = &deep_hashes[offset];
        deep_fork[offset].pprev =
            offset == 0 ? nullptr : &deep_fork[offset - 1];
    }
    BOOST_CHECK(!llmq::IsLiveChainLockCandidateAdmissible(
        *schedule, active[10], deep_fork.back()));

    std::array<CBlockIndex, 5> current_side_fork;
    std::array<uint256, 5> current_side_hashes;
    for (std::size_t offset{0}; offset < current_side_fork.size(); ++offset) {
        current_side_hashes[offset] = NonNullHash(53'000 + offset);
        current_side_fork[offset].nHeight =
            876 + static_cast<int32_t>(offset);
        current_side_fork[offset].phashBlock =
            &current_side_hashes[offset];
        current_side_fork[offset].pprev =
            offset == 0 ? &active[5] : &current_side_fork[offset - 1];
    }

    // Recovery uses the same current-round fork bound as LIVE: a competing
    // target may win while it shares the H-5 boundary, but expires with the
    // round and a deeper fork is never admissible.
    BOOST_CHECK(llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], active[10]));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], active[5]));
    BOOST_CHECK(llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[15], current_side_fork.back()));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[20], active[10]));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[20], current_side_fork.back()));
    BOOST_CHECK(!llmq::IsCurrentChainLockCatchupCandidateAdmissible(
        *schedule, active[10], deep_fork.back()));
}

BOOST_AUTO_TEST_CASE(
    current_btcc_selection_waits_for_and_then_obeys_the_exact_carrier)
{
    const uint256 genesis{NonNullHash(54'000)};
    const auto config{CatchupStoreConfig()};
    std::array<CBlockIndex, 17> chain;
    std::array<uint256, 17> hashes;
    LOCK(cs_main);
    for (std::size_t offset{0}; offset < chain.size(); ++offset) {
        hashes[offset] = offset == 0
            ? config.anchor.block_hash
            : NonNullHash(54'100 + offset);
        chain[offset].nHeight = 864 + static_cast<int32_t>(offset);
        chain[offset].phashBlock = &hashes[offset];
        chain[offset].pprev = offset == 0 ? nullptr : &chain[offset - 1];
        chain[offset].nStatus = static_cast<BlockStatus>(
            BLOCK_VALID_SCRIPTS | BLOCK_PQ_RECEIPT_INDEX_VALIDATED);
    }
    CBlockIndex& source{chain[6]};
    CBlockIndex& pre_carrier_target{chain[11]};
    CBlockIndex& carrier_target{chain[16]};
    source.btcpPrevCommitment = NonNullHash(54'200);
    carrier_target.btcpPrevCommitment = NonNullHash(54'201);

    auto advance{MakeCatchupChainLock(
        870, 865, chain[1].GetBlockHash(), 54'300)};
    advance.statement.block_hash = source.GetBlockHash();
    advance.statement.accepted_btcc_cursor = llmq::pq::BTCCursor{
        source.nHeight, source.GetBlockHash(), source.btcpPrevCommitment};
    advance.statement.btcc_advance = llmq::pq::BTCCAdvance::ADVANCE;
    BOOST_REQUIRE(advance.IsStructurallyValid());
    const llmq::pq::FinalChainLockRecordMetadata advance_metadata{
        advance.GetLogicalId(genesis), advance.GetWitnessId(genesis),
        advance.statement};

    const auto before_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, pre_carrier_target, &advance_metadata)};
    BOOST_REQUIRE(before_carrier);
    BOOST_CHECK(before_carrier->previous_cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(before_carrier->selected.cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(before_carrier->selected.advance ==
                llmq::pq::BTCCAdvance::KEEP);
    BOOST_CHECK(!before_carrier->cursor_reconciliation);
    auto inconsistent_metadata{advance_metadata};
    inconsistent_metadata.logical_id = NonNullHash(54'302);
    BOOST_CHECK(!llmq::SelectCurrentChainLockBTCC(
        genesis, config, pre_carrier_target, &inconsistent_metadata));

    const auto at_null_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &advance_metadata)};
    BOOST_REQUIRE(at_null_carrier);
    BOOST_CHECK(at_null_carrier->previous_cursor.IsNull());
    BOOST_CHECK(at_null_carrier->selected.advance ==
                llmq::pq::BTCCAdvance::ADVANCE);
    BOOST_CHECK_EQUAL(at_null_carrier->selected.cursor.sys_height, 880);
    BOOST_REQUIRE(at_null_carrier->cursor_reconciliation);
    BOOST_CHECK_EQUAL(
        at_null_carrier->cursor_reconciliation->carrier_height, 880);

    // Catching up directly to KEEP(C) retains no ADVANCE archive, but its
    // signed cursor-vs-receipt gap yields the identical objective proof.
    auto keep{MakeCatchupChainLock(
        875, 870, source.GetBlockHash(), 54'301)};
    keep.statement.block_hash = pre_carrier_target.GetBlockHash();
    keep.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    keep.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    const llmq::pq::FinalChainLockRecordMetadata keep_metadata{
        keep.GetLogicalId(genesis), keep.GetWitnessId(genesis), keep.statement};
    const auto caught_up_at_null_carrier{
        llmq::SelectCurrentChainLockBTCC(
            genesis, config, carrier_target, &keep_metadata)};
    BOOST_REQUIRE(caught_up_at_null_carrier);
    BOOST_REQUIRE(caught_up_at_null_carrier->cursor_reconciliation);
    BOOST_CHECK(caught_up_at_null_carrier->previous_cursor.IsNull());

    // A non-null carrier advances the indexed receipt cursor to C, so there is
    // no rollback proof and both durable/indexed views select from C.
    llmq::pq::BTCCReceipt receipt;
    receipt.chainlock_target_height = advance.statement.height;
    receipt.chainlock_target_hash = advance.statement.block_hash;
    receipt.chainlock_logical_id = advance.GetLogicalId(genesis);
    receipt.accepted_cursor = advance.statement.accepted_btcc_cursor;
    const auto applied{llmq::pq::ApplyBTCCReceiptState(
        genesis, config.chainlock_schedule, config.btcc_schedule,
        carrier_target.nHeight, carrier_target.GetBlockHash(), {}, receipt)};
    BOOST_REQUIRE(applied);
    carrier_target.pqBTCCReceiptCursorHeight = applied->cursor.sys_height;
    carrier_target.pqBTCCReceiptCursorSysHash = applied->cursor.sys_hash;
    carrier_target.pqBTCCReceiptCursorBTCHash = applied->cursor.btc_hash;
    carrier_target.pqBTCCReceiptStateHash = applied->cumulative_hash;
    carrier_target.pqBTCCReceiptLogicalId = receipt.chainlock_logical_id;
    const auto at_nonnull_carrier{llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &keep_metadata)};
    BOOST_REQUIRE(at_nonnull_carrier);
    BOOST_CHECK(at_nonnull_carrier->previous_cursor ==
                advance.statement.accepted_btcc_cursor);
    BOOST_CHECK(!at_nonnull_carrier->cursor_reconciliation);

    // Equal heights with a different cursor identity are never ordered.
    carrier_target.pqBTCCReceiptCursorSysHash = NonNullHash(54'999);
    BOOST_CHECK(!llmq::SelectCurrentChainLockBTCC(
        genesis, config, carrier_target, &keep_metadata));
}

BOOST_AUTO_TEST_CASE(
    current_side_candidates_cannot_orphan_durable_preseal_state)
{
    // Exact-successor LIVE and rolling CURRENT_CATCHUP share this publication
    // guard. Active candidates and non-current marker recovery are unchanged.
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/false,
        /*has_payment_audit_preseal=*/false));
    BOOST_CHECK(llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/false));
    BOOST_CHECK(llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/false,
        /*has_payment_audit_preseal=*/true));
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/true,
        /*current_round_candidate=*/true,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/true));
    BOOST_CHECK(!llmq::IsCurrentChainLockCandidateBlockedByPreseal(
        /*candidate_is_active=*/false,
        /*current_round_candidate=*/false,
        /*has_btcc_preseal=*/true,
        /*has_payment_audit_preseal=*/true));
}

BOOST_AUTO_TEST_CASE(
    marker_recovery_cannot_self_choose_an_exact_local_cursor)
{
    const llmq::pq::BTCCursor local{
        870, NonNullHash(55'000), NonNullHash(55'001)};
    const llmq::pq::BTCCursor alternate{
        865, NonNullHash(55'002), NonNullHash(55'003)};

    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/true,
        local, local));
    BOOST_CHECK(!llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/true,
        alternate, local));

    // P>S has no locally retained predecessor certificate, while CURRENT
    // derives its exceptional cursor transition from the candidate branch.
    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/false,
        /*declared_predecessor_is_local=*/false,
        alternate, local));
    BOOST_CHECK(llmq::IsHistoricalLocalPredecessorCursorCompatible(
        /*current_round_candidate=*/true,
        /*declared_predecessor_is_local=*/true,
        alternate, local));
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

    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/true,
        /*historical_resolved=*/true));
    BOOST_CHECK(llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/true,
        /*historical_resolved=*/false));
    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/false,
        /*historical_resolved=*/false));
    BOOST_CHECK(!llmq::MustRetryPaymentAuditCertificateContext(
        /*historical_required=*/false,
        /*historical_resolved=*/true));
}

BOOST_AUTO_TEST_CASE(local_chainlock_share_retry_is_journal_replay_only)
{
    using llmq::pq::ShareCollectionResult;
    BOOST_CHECK(llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::DUPLICATE));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/false, ShareCollectionResult::DUPLICATE));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::ACCEPTED));
    BOOST_CHECK(!llmq::ShouldRetryLocalChainLockShareRelay(
        /*journal_replayed=*/true, ShareCollectionResult::REJECTED));
}

BOOST_AUTO_TEST_CASE(payment_audit_finalization_retry_is_rate_limited)
{
    using Microseconds = std::chrono::microseconds;
    const Microseconds first_attempt{100'000'000};

    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt, std::nullopt));
    BOOST_CHECK(!llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt + std::chrono::seconds{29}, first_attempt));
    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt + std::chrono::seconds{30}, first_attempt));
    BOOST_CHECK(llmq::IsPaymentAuditFinalizationRetryDue(
        first_attempt - std::chrono::seconds{1}, first_attempt));
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

BOOST_AUTO_TEST_CASE(chainlock_recovery_survives_operational_kill_switch)
{
    BOOST_CHECK(llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/false,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/true,
        /*persistence_failed=*/false));
    BOOST_CHECK(!llmq::ShouldVerifyChainLockCertificate(
        /*configured_and_healthy=*/true,
        /*persisted_import_pending=*/false,
        /*persistence_failed=*/true));
}

BOOST_AUTO_TEST_CASE(updated_receipt_anchor_routes_exact_target_to_catchup)
{
    constexpr int32_t local_best{2305};
    constexpr int32_t receipt_anchor{2310};
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
    BOOST_CHECK(!llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/true,
        /*probation_gc_complete=*/true));
    BOOST_CHECK(llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/false,
        /*probation_gc_complete=*/true));
    BOOST_CHECK(llmq::ShouldRunPaymentAuditDurableGC(
        /*reuse_archive_checkpoint=*/true,
        /*probation_gc_complete=*/false));

    auto refreshed{checkpoint};
    // Authorizer-only changes permit archive and completed state-GC reuse;
    // the five-second enforcement pass therefore performs no full flush.
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

BOOST_AUTO_TEST_CASE(accepted_winner_preserves_only_its_exact_successor_view)
{
    const auto schedule{llmq::pq::MakeChainLockScheduleConfig(
        /*epoch_origin=*/0)};
    BOOST_REQUIRE(schedule);

    llmq::pq::ChainLockStatement winner;
    winner.height = 865;
    winner.block_hash = NonNullHash(11);
    winner.accepted_btcc_cursor.sys_height = 42;
    winner.accepted_btcc_cursor.sys_hash = NonNullHash(13);
    winner.accepted_btcc_cursor.btc_hash = NonNullHash(14);

    llmq::pq::ChainLockStatement collector;
    collector.height = 870;
    collector.previous_chainlock_height = winner.height;
    collector.previous_chainlock_hash = winner.block_hash;
    collector.previous_btcc_cursor = winner.accepted_btcc_cursor;
    BOOST_CHECK(llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, collector, winner));

    auto stale{collector};
    stale.previous_chainlock_height = 864;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, stale, winner));

    auto skipped{collector};
    skipped.height = 875;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, skipped, winner));

    auto wrong_hash{collector};
    wrong_hash.previous_chainlock_hash = NonNullHash(12);
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, wrong_hash, winner));

    auto wrong_cursor{collector};
    ++wrong_cursor.previous_btcc_cursor.sys_height;
    BOOST_CHECK(!llmq::IsChainLockCollectorOnAcceptedSuccessorView(
        *schedule, wrong_cursor, winner));
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
    auto& relay_member{rosters[1].members[9]};
    relay_member.eligible = true;
    relay_member.pro_tx_hash = authenticated_relay;
    relay_member.child_root.emplace();
    const uint256 ineligible_relay{NonNullHash(24)};
    auto& ineligible_member{rosters[2].members[10]};
    ineligible_member.pro_tx_hash = ineligible_relay;
    ineligible_member.child_root.emplace();
    const uint256 rootless_relay{NonNullHash(25)};
    auto& rootless_member{rosters[3].members[11]};
    rootless_member.eligible = true;
    rootless_member.pro_tx_hash = rootless_relay;
    auto& null_member{rosters[3].members[12]};
    null_member.eligible = true;
    null_member.child_root.emplace();

    llmq::pq::ChainLockShareTranscript transcript;
    transcript.quorum_epoch = roster.descriptor.epoch;
    transcript.quorum_base_hash = roster.descriptor.base_hash;
    transcript.member_index = 3;
    transcript.member_pro_tx_hash = original_signer;
    const auto relay_recipients{
        llmq::BuildChainLockRelayRecipients(rosters)};
    BOOST_CHECK(!relay_recipients.contains(uint256{}));

    BOOST_CHECK(original_signer != authenticated_relay);
    BOOST_CHECK(llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, authenticated_relay, transcript));

    transcript.member_pro_tx_hash = NonNullHash(23);
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, authenticated_relay, transcript));
    transcript.member_pro_tx_hash = original_signer;
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, NonNullHash(26), transcript));
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, ineligible_relay, transcript));
    BOOST_CHECK(!llmq::IsAuthorizedChainLockShareRelay(
        rosters, relay_recipients, rootless_relay, transcript));
}

BOOST_FIXTURE_TEST_CASE(
    updated_receipt_anchor_is_a_valid_historical_range_boundary,
    TestChain100Setup)
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
    chainman.ResetIbd(PQHistoryAuthState::PENDING);
    BOOST_CHECK(chainman.IsInitialBlockDownload());
    {
        LOCK(::cs_main);
        BOOST_CHECK(chainman.IsBaseBlockSyncComplete());
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
