// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_store.h>

#include <test/util/setup_common.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>

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
    for (std::size_t member{0}; member < count; ++member) {
        bitmap[member / 8] |= static_cast<uint8_t>(uint8_t{1} << (member % 8));
    }
}

FinalChainLock MakeChainLock(int32_t height,
                             int32_t previous_height,
                             const uint256& previous_hash,
                             uint64_t salt)
{
    FinalChainLock chainlock;
    chainlock.statement.height = height;
    chainlock.statement.block_hash = NonNullHash(10000 + salt);
    chainlock.statement.previous_chainlock_height = previous_height;
    chainlock.statement.previous_chainlock_hash = previous_hash;
    chainlock.statement.quorum_context_hash = NonNullHash(20000 + salt);
    chainlock.statement.payment_probation_state_hash = NonNullHash(30'000);
    chainlock.selected_quorum_mask = 0b0111;
    chainlock.signatures.resize(FINAL_SIGNATURE_COUNT);
    for (auto& authenticated : chainlock.signatures) {
        authenticated.key_proof.public_key[0] = 1;
    }
    for (std::size_t slot{0}; slot < REQUIRED_QUORUMS; ++slot) {
        SetFirstMembers(chainlock.signer_bitmaps[slot], QUORUM_THRESHOLD);
    }
    chainlock.signatures[0].signature[0] = static_cast<uint8_t>(salt);
    return chainlock;
}

BTCCursor MakeCursor(int32_t height, uint64_t salt)
{
    return BTCCursor{height, NonNullHash(30000 + salt),
                     NonNullHash(40000 + salt)};
}

PaymentAuditReceiptState MakePaymentAuditReceiptState(
    int32_t carrier_height, uint32_t epoch, uint64_t salt)
{
    return PaymentAuditReceiptState{
        PaymentAuditReceiptCursor{
            carrier_height, epoch, NonNullHash(50'000 + salt),
            NonNullHash(60'000 + salt), NonNullHash(70'000 + salt)},
        NonNullHash(80'000 + salt)};
}

ChainLockFinalityStoreConfig MakeConfig(std::size_t cache_capacity = 4,
                                        std::size_t recent_capacity = 2)
{
    ChainLockFinalityStoreConfig config;
    config.chainlock_schedule = *MakeChainLockScheduleConfig(0);
    config.btcc_schedule.candidate_origin = 870;
    config.anchor.height = 864;
    config.anchor.block_hash = NonNullHash(864);
    config.seen_logical_capacity = cache_capacity;
    config.seen_witness_capacity = cache_capacity;
    config.rejected_witness_capacity = cache_capacity;
    config.recent_chainlocks_capacity = recent_capacity;
    return config;
}

BTCCCursorReconciliationProof MakeReconciliationProof(
    const FinalChainLock& durable, uint64_t salt)
{
    BTCCCursorReconciliationProof proof;
    proof.carrier_height =
        durable.statement.accepted_btcc_cursor.sys_height +
        static_cast<int32_t>(PQ_BTCC_NEVM_LAG);
    proof.carrier_hash = NonNullHash(90'000 + salt);
    proof.carrier_parent_hash = NonNullHash(91'000 + salt);
    proof.skipped_cursor = durable.statement.accepted_btcc_cursor;
    proof.previous_receipt_state = durable.statement.btcc_receipt_state;
    proof.current_receipt_state = durable.statement.btcc_receipt_state;
    return proof;
}

class TestFinalityContext final : public ChainLockFinalityContext {
public:
    bool known{true};
    bool scripts{true};
    bool special{true};
    bool descendant{true};
    bool btcc{true};
    std::optional<BTCCCursorReconciliationProof> btcc_cursor_reconciliation;
    bool reject_recheck{false};
    uint64_t generation{1};
    mutable ChainLockCandidateAdmission last_admission{
        ChainLockCandidateAdmission::LIVE};
    mutable std::map<int32_t, uint256> accepted_branch;

    std::optional<ChainLockCandidateContext> PrepareCandidate(
        const ChainLockCandidateContextRequest& request) const override
    {
        return MakeContext(request);
    }

    std::optional<ChainLockCandidateContext> RecheckCandidate(
        const ChainLockCandidateContextRequest& request,
        const ChainLockCandidateContext& prepared) const override
    {
        if (reject_recheck || prepared.context_token != NonNullHash(generation)) {
            return std::nullopt;
        }
        return MakeContext(request);
    }

    AcceptedBranchRelation QueryAcceptedBranch(
        int32_t height,
        const uint256& block_hash,
        int32_t,
        const uint256&) const override
    {
        const auto found{accepted_branch.find(height)};
        if (found == accepted_branch.end()) return AcceptedBranchRelation::UNKNOWN;
        return found->second == block_hash ? AcceptedBranchRelation::MATCH
                                           : AcceptedBranchRelation::CONFLICT;
    }

private:
    ChainLockCandidateContext MakeContext(
        const ChainLockCandidateContextRequest& request) const
    {
        last_admission = request.admission;
        return ChainLockCandidateContext{
            known, scripts, special, descendant, descendant, btcc,
            request.statement.height, request.statement.block_hash,
            NonNullHash(generation),
            btcc_cursor_reconciliation};
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_chainlock_store_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(catchup_historical_proof_scans_once_per_branch_context)
{
    int64_t now_ms{0};
    CatchupHistoricalProofCache cache{
        /*capacity=*/2, [&] { return now_ms; }};
    const uint256 branch_a{NonNullHash(501)};
    const uint256 branch_b{NonNullHash(502)};
    const uint256 context_a{NonNullHash(503)};
    const uint256 context_b{NonNullHash(504)};
    const BTCCReceiptState proof_a{
        MakeCursor(870, 501), NonNullHash(505)};
    const BTCCReceiptState proof_b{
        MakeCursor(880, 502), NonNullHash(506)};
    std::size_t scans{0};

    auto first{cache.GetOrCompute(branch_a, context_a, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_a};
    })};
    BOOST_REQUIRE(first);
    BOOST_CHECK(*first == proof_a);
    auto repeated{cache.GetOrCompute(branch_a, context_a, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_b};
    })};
    BOOST_REQUIRE(repeated);
    BOOST_CHECK(*repeated == proof_a);
    BOOST_CHECK_EQUAL(scans, 1U);
    BOOST_CHECK_EQUAL(cache.ComputationsForTesting(), 1U);

    BOOST_REQUIRE(cache.GetOrCompute(branch_a, context_b, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_b};
    }));
    BOOST_CHECK_EQUAL(scans, 2U);
    BOOST_CHECK_EQUAL(cache.SizeForTesting(), 2U);

    // A tip/branch token change drops all old candidate proofs before the
    // first scan on the replacement best-work branch.
    BOOST_REQUIRE(cache.GetOrCompute(branch_b, context_a, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_b};
    }));
    BOOST_CHECK_EQUAL(scans, 3U);
    BOOST_CHECK_EQUAL(cache.SizeForTesting(), 1U);
    BOOST_CHECK_EQUAL(cache.ComputationsForTesting(), 3U);

    const uint256 invalid_context{NonNullHash(507)};
    auto invalid{cache.GetOrCompute(branch_b, invalid_context, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{};
    })};
    BOOST_CHECK(!invalid);
    auto repeated_invalid{cache.GetOrCompute(
        branch_b, invalid_context, [&] {
            ++scans;
            return CatchupHistoricalProofCache::BuildResult{proof_a};
        })};
    BOOST_CHECK(!repeated_invalid);
    BOOST_CHECK_EQUAL(scans, 4U);
    BOOST_CHECK_EQUAL(cache.ComputationsForTesting(), 4U);

    const uint256 transient_context{NonNullHash(508)};
    auto transient{cache.GetOrCompute(branch_b, transient_context, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{
            std::nullopt, /*definitive=*/false};
    })};
    BOOST_CHECK(!transient);
    auto backed_off{cache.GetOrCompute(branch_b, transient_context, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_a};
    })};
    BOOST_CHECK(!backed_off);
    BOOST_CHECK_EQUAL(scans, 5U);
    BOOST_CHECK_EQUAL(cache.ComputationsForTesting(), 5U);

    now_ms += 1000;
    auto recovered{cache.GetOrCompute(branch_b, transient_context, [&] {
        ++scans;
        return CatchupHistoricalProofCache::BuildResult{proof_a};
    })};
    BOOST_REQUIRE(recovered);
    BOOST_CHECK(*recovered == proof_a);
    BOOST_CHECK_EQUAL(scans, 6U);
    BOOST_CHECK_EQUAL(cache.ComputationsForTesting(), 6U);
}

BOOST_AUTO_TEST_CASE(first_verified_statement_wins_and_queries_are_branch_aware)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(1), MakeConfig(), context};
    const auto first{MakeChainLock(865, 864, NonNullHash(864), 1)};

    auto prepared{store.PrepareCandidate(first)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, first, true));
    context.accepted_branch.emplace(861, NonNullHash(861));

    BOOST_CHECK(store.HasChainLock(865, first.statement.block_hash));
    BOOST_CHECK(store.HasChainLock(861, NonNullHash(861)));
    BOOST_CHECK(store.HasConflictingChainLock(861, NonNullHash(999)));
    BOOST_CHECK(store.GetBest() && *store.GetBest() == first);
    BOOST_CHECK(store.GetByWitness(first.GetWitnessId(NonNullHash(1))));

    const auto conflict{MakeChainLock(865, 864, NonNullHash(864), 2)};
    BOOST_CHECK(!store.PrepareCandidate(conflict));
    BOOST_CHECK(store.GetBest()->statement.block_hash == first.statement.block_hash);
}

BOOST_AUTO_TEST_CASE(local_import_defers_only_unknown_anchor_ancestry)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(1), MakeConfig(), context};
    const uint256 candidate{NonNullHash(859)};

    BOOST_CHECK(store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/true));
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/false));

    context.accepted_branch.emplace(859, candidate);
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/true));
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/false));

    context.accepted_branch[859] = NonNullHash(999);
    BOOST_CHECK(store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/true));
    BOOST_CHECK(store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/false));
}

BOOST_AUTO_TEST_CASE(witness_dedup_does_not_suppress_an_alternate_witness)
{
    const uint256 genesis{NonNullHash(2)};
    TestFinalityContext context;
    ChainLockFinalityStore store{genesis, MakeConfig(), context};
    const auto bad_witness{MakeChainLock(865, 864, NonNullHash(864), 3)};
    auto good_witness{bad_witness};
    good_witness.signatures.back().signature[0] ^= 1;
    BOOST_REQUIRE(bad_witness.GetLogicalId(genesis) == good_witness.GetLogicalId(genesis));
    BOOST_REQUIRE(bad_witness.GetWitnessId(genesis) != good_witness.GetWitnessId(genesis));

    auto bad_prepared{store.PrepareCandidate(bad_witness)};
    BOOST_REQUIRE(bad_prepared);
    BOOST_CHECK(!store.AcceptVerified(*bad_prepared, bad_witness, false));
    BOOST_CHECK(!store.PrepareCandidate(bad_witness));

    auto good_prepared{store.PrepareCandidate(good_witness)};
    BOOST_REQUIRE(good_prepared);
    BOOST_CHECK(store.AcceptVerified(*good_prepared, good_witness, true));
}

BOOST_AUTO_TEST_CASE(preparation_and_acceptance_fail_closed_on_context_changes)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(3), MakeConfig(), context};
    const auto chainlock{MakeChainLock(865, 864, NonNullHash(864), 4)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    context.special = false;
    BOOST_CHECK(!store.PrepareCandidate(chainlock, &error));
    BOOST_CHECK(error == ChainLockFinalityError::BLOCK_NOT_FULLY_VALIDATED);

    context.special = true;
    auto prepared{store.PrepareCandidate(chainlock, &error)};
    BOOST_REQUIRE(prepared);
    ++context.generation;
    BOOST_CHECK(!store.AcceptVerified(*prepared, chainlock, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    BOOST_CHECK(!store.GetBest());
}

BOOST_AUTO_TEST_CASE(durable_accept_failure_leaves_store_unchanged)
{
    TestFinalityContext context;
    bool allow_persistence{false};
    std::size_t callback_count{0};
    ChainLockFinalityStore store{
        NonNullHash(30), MakeConfig(), context,
        [&](const FinalChainLock&) {
            ++callback_count;
            return allow_persistence;
        }};
    const auto chainlock{MakeChainLock(865, 864, NonNullHash(864), 30)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    auto prepared{store.PrepareCandidate(chainlock, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!store.AcceptVerified(*prepared, chainlock, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PERSISTENCE_FAILURE);
    BOOST_CHECK(!store.GetBest());
    BOOST_CHECK_EQUAL(store.RecentSizeForTesting(), 0U);
    BOOST_CHECK_EQUAL(callback_count, 1U);

    store.AbandonPrepared(*prepared);
    allow_persistence = true;
    prepared = store.PrepareCandidate(chainlock, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(store.AcceptVerified(*prepared, chainlock, true, &error));
    BOOST_CHECK(store.GetBest() && *store.GetBest() == chainlock);
    BOOST_CHECK_EQUAL(callback_count, 2U);
}

BOOST_AUTO_TEST_CASE(precontext_crypto_rejection_is_deduplicated)
{
    TestFinalityContext context;
    const uint256 genesis{NonNullHash(31)};
    ChainLockFinalityStore store{genesis, MakeConfig(), context};
    const auto chainlock{MakeChainLock(865, 864, NonNullHash(864), 31)};
    const uint256 witness_id{chainlock.GetWitnessId(genesis)};

    BOOST_CHECK(!store.AlreadyHaveWitness(witness_id));
    store.RejectWitness(chainlock);
    BOOST_CHECK(store.AlreadyHaveWitness(witness_id));
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.PrepareCatchupCandidate(chainlock, &error));
    BOOST_CHECK(error == ChainLockFinalityError::REJECTED_WITNESS);
}

BOOST_AUTO_TEST_CASE(live_certificates_chain_exactly_and_caches_remain_bounded)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(4), MakeConfig(2, 2), context};
    auto previous{MakeChainLock(865, 864, NonNullHash(864), 10)};
    auto prepared{store.PrepareCandidate(previous)};
    BOOST_REQUIRE(prepared && store.AcceptVerified(*prepared, previous, true));

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    const auto fabricated_predecessor{
        MakeChainLock(885, 880, NonNullHash(880), 11)};
    BOOST_CHECK(!store.PrepareCandidate(fabricated_predecessor, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    for (int32_t height : {870, 875}) {
        auto next{MakeChainLock(height, previous.statement.height,
                                previous.statement.block_hash, height)};
        next.statement.previous_btcc_cursor =
            previous.statement.accepted_btcc_cursor;
        next.statement.accepted_btcc_cursor = previous.statement.accepted_btcc_cursor;
        prepared = store.PrepareCandidate(next);
        BOOST_REQUIRE(prepared && store.AcceptVerified(*prepared, next, true));
        previous = std::move(next);
    }

    BOOST_CHECK_EQUAL(store.RecentSizeForTesting(), 2U);
    BOOST_CHECK_LE(store.SeenLogicalSizeForTesting(), 2U);
    BOOST_CHECK_LE(store.SeenWitnessSizeForTesting(), 2U);
    BOOST_CHECK(!store.GetByWitness(MakeChainLock(865, 864, NonNullHash(864), 10)
                                        .GetWitnessId(NonNullHash(4))));

    auto wrong_predecessor{
        MakeChainLock(880, previous.statement.height, NonNullHash(123), 20)};
    context.descendant = false;
    BOOST_CHECK(!store.PrepareCandidate(wrong_predecessor));

    auto bad_btcc{MakeChainLock(880, previous.statement.height,
                                previous.statement.block_hash, 21)};
    context.descendant = true;
    context.btcc = false;
    BOOST_CHECK(!store.PrepareCandidate(bad_btcc));
}

BOOST_AUTO_TEST_CASE(all_admissions_require_the_unique_predecessor_successor)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(400), MakeConfig(), context};
    auto skipped{MakeChainLock(870, 864, NonNullHash(864), 400)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    BOOST_CHECK(!store.PrepareCandidate(skipped, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INELIGIBLE_HEIGHT);
    BOOST_CHECK(!store.PreparePersistedCandidate(skipped, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INELIGIBLE_HEIGHT);
    BOOST_CHECK(!store.PrepareCatchupCandidate(skipped, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INELIGIBLE_HEIGHT);

    skipped.statement.accepted_btcc_cursor = MakeCursor(870, 400);
    skipped.statement.btcc_advance = BTCCAdvance::ADVANCE;
    BOOST_CHECK(!store.PrepareReceiptArchiveCandidate(skipped, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INELIGIBLE_HEIGHT);
    BOOST_CHECK(!store.PreparePresealReceiptCandidate(skipped, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INELIGIBLE_HEIGHT);
}

BOOST_AUTO_TEST_CASE(persisted_latest_restore_is_separate_from_live_admission)
{
    const uint256 genesis{NonNullHash(40)};
    TestFinalityContext context;
    std::size_t durable_callback_count{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context,
        [&](const FinalChainLock&) {
            ++durable_callback_count;
            return true;
        }};
    auto persisted{MakeChainLock(885, 880, NonNullHash(880), 40)};
    persisted.statement.previous_btcc_cursor = MakeCursor(870, 1);
    persisted.statement.accepted_btcc_cursor =
        persisted.statement.previous_btcc_cursor;

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.PrepareCandidate(persisted, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto prepared{store.PreparePersistedCandidate(persisted, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(context.last_admission ==
                ChainLockCandidateAdmission::TRUSTED_PERSISTENCE);
    BOOST_CHECK(prepared->admission ==
                ChainLockCandidateAdmission::TRUSTED_PERSISTENCE);
    BOOST_CHECK(!store.AcceptVerified(*prepared, persisted, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    BOOST_REQUIRE(store.AcceptPersistedVerified(
        *prepared, persisted, true, &error));
    BOOST_CHECK(store.GetBest() && *store.GetBest() == persisted);
    BOOST_CHECK_EQUAL(durable_callback_count, 0U);

    const auto second_import{
        MakeChainLock(895, 890, NonNullHash(890), 41)};
    BOOST_CHECK(!store.PreparePersistedCandidate(second_import, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PERSISTED_IMPORT_NOT_EMPTY);
}

BOOST_AUTO_TEST_CASE(catchup_rebases_repeatably_across_missing_predecessors)
{
    const uint256 genesis{NonNullHash(401)};
    TestFinalityContext context;
    std::size_t catchup_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&) {
            ++catchup_writes;
            return true;
        }};

    const auto local{MakeChainLock(865, 864, NonNullHash(864), 401)};
    auto prepared{store.PrepareCandidate(local)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, local, true));

    // The current certificate C names its actual immediate predecessor P=880,
    // which this node missed. LIVE correctly rejects it; CATCHUP may bridge the
    // gap only after the integration proves both local S=865 and P are active
    // ancestors and recomputes the exact receipt state.
    const auto first_rebase{MakeChainLock(885, 880, NonNullHash(880), 402)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.PrepareCandidate(first_rebase, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);
    prepared = store.PrepareCatchupCandidate(first_rebase, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(context.last_admission == ChainLockCandidateAdmission::CATCHUP);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, first_rebase, true, [] { return true; }, {}, &error));
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == first_rebase);

    // Exact chaining resumes through LIVE after the rebase.
    const auto exact{MakeChainLock(
        890, first_rebase.statement.height,
        first_rebase.statement.block_hash, 403)};
    prepared = store.PrepareCandidate(exact, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, exact, true, &error));

    // A later outage may require another authenticated gap rebase; the audit
    // marker is not a one-shot liveness fuse.
    const auto second_rebase{MakeChainLock(915, 910, NonNullHash(910), 404)};
    prepared = store.PrepareCatchupCandidate(second_rebase, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, second_rebase, true, [] { return true; }, {}, &error));
    BOOST_CHECK_EQUAL(catchup_writes, 2U);
    BOOST_CHECK(*store.GetBest() == second_rebase);

    const auto predecessor_before_local{
        MakeChainLock(905, 900, NonNullHash(900), 405)};
    BOOST_CHECK(!store.PrepareCatchupCandidate(
        predecessor_before_local, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);
}

BOOST_AUTO_TEST_CASE(
    current_catchup_may_reconcile_a_cursor_view_but_never_regress_durable_state)
{
    const uint256 genesis{NonNullHash(420)};
    TestFinalityContext context;
    std::size_t catchup_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&) {
            ++catchup_writes;
            return true;
        }};

    const BTCCursor durable_cursor{MakeCursor(870, 420)};
    const BTCCReceiptState durable_receipt{
        durable_cursor, NonNullHash(421)};
    const PaymentAuditReceiptState durable_payment{
        MakePaymentAuditReceiptState(870, 1, 422)};
    const uint256 durable_probation{NonNullHash(423)};

    auto local{MakeChainLock(875, 870, NonNullHash(870), 424)};
    local.statement.previous_btcc_cursor = durable_cursor;
    local.statement.accepted_btcc_cursor = durable_cursor;
    local.statement.btcc_receipt_state = durable_receipt;
    local.statement.payment_audit_receipt_state = durable_payment;
    local.statement.payment_probation_state_hash = durable_probation;
    auto prepared{store.PreparePersistedCandidate(local)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptPersistedVerified(*prepared, local, true));

    const BTCCursor alternate_previous{MakeCursor(865, 425)};
    const BTCCursor advanced_cursor{MakeCursor(880, 426)};
    const auto make_recovery = [&](uint64_t salt) {
        auto candidate{MakeChainLock(
            880, local.statement.height, local.statement.block_hash, salt)};
        candidate.statement.previous_btcc_cursor = alternate_previous;
        candidate.statement.accepted_btcc_cursor = advanced_cursor;
        candidate.statement.btcc_advance = BTCCAdvance::ADVANCE;
        candidate.statement.btcc_receipt_state = durable_receipt;
        candidate.statement.payment_audit_receipt_state = durable_payment;
        candidate.statement.payment_probation_state_hash =
            durable_probation;
        return candidate;
    };

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    const auto recovery{make_recovery(427)};
    BOOST_CHECK(!store.PrepareCandidate(recovery, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto regressed_cursor{make_recovery(428)};
    regressed_cursor.statement.accepted_btcc_cursor = alternate_previous;
    regressed_cursor.statement.btcc_advance = BTCCAdvance::KEEP;
    regressed_cursor.statement.btcc_receipt_state = {};
    BOOST_CHECK(!store.PrepareCatchupCandidate(regressed_cursor, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto regressed_receipt{make_recovery(429)};
    regressed_receipt.statement.btcc_receipt_state = {};
    BOOST_CHECK(!store.PrepareCatchupCandidate(regressed_receipt, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto regressed_payment{make_recovery(430)};
    regressed_payment.statement.payment_audit_receipt_state = {};
    BOOST_CHECK(!store.PrepareCatchupCandidate(regressed_payment, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto changed_probation{make_recovery(431)};
    changed_probation.statement.payment_probation_state_hash =
        NonNullHash(432);
    BOOST_CHECK(!store.PrepareCatchupCandidate(changed_probation, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    prepared = store.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error));
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == recovery);
}

BOOST_AUTO_TEST_CASE(
    candidate_bound_null_carrier_reconciles_heterogeneous_durable_views)
{
    const uint256 genesis{NonNullHash(433)};
    TestFinalityContext ahead_context;
    TestFinalityContext caught_up_context;
    TestFinalityContext behind_context;
    bool ahead_reconciliation{false};
    bool caught_up_reconciliation{false};
    bool behind_reconciliation{true};
    ChainLockFinalityStore ahead{
        genesis, MakeConfig(), ahead_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation) {
            ahead_reconciliation = reconciliation.has_value();
            return true;
        }};
    ChainLockFinalityStore caught_up{
        genesis, MakeConfig(), caught_up_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation) {
            caught_up_reconciliation = reconciliation.has_value();
            return true;
        }};
    ChainLockFinalityStore behind{
        genesis, MakeConfig(), behind_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation) {
            behind_reconciliation = reconciliation.has_value();
            return true;
        }};

    const auto prior{MakeChainLock(865, 864, NonNullHash(864), 433)};
    for (ChainLockFinalityStore* store : {&ahead, &caught_up, &behind}) {
        auto prepared{store->PrepareCandidate(prior)};
        BOOST_REQUIRE(prepared);
        BOOST_REQUIRE(store->AcceptVerified(*prepared, prior, true));
    }

    auto advance{MakeChainLock(870, 865, prior.statement.block_hash, 434)};
    advance.statement.accepted_btcc_cursor =
        BTCCursor{870, advance.statement.block_hash, NonNullHash(43'400)};
    advance.statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto prepared{ahead.PrepareCandidate(advance)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(ahead.AcceptVerified(*prepared, advance, true));
    BOOST_REQUIRE(ahead.GetUnsealedBTCC());

    // H+5 does not commit to H+10's carrier and cannot use a descendant tip's
    // null receipt as authority to roll back the durable ADVANCE.
    const auto premature{
        MakeChainLock(875, 870, advance.statement.block_hash, 435)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!ahead.PrepareCatchupCandidate(premature, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    // A normal T+5 KEEP carries C forward before C's carrier exists. A node
    // that catches up directly to this certificate has the same durable gap
    // without retaining the original ADVANCE as an unsealed archive row.
    auto keep{MakeChainLock(875, 870, advance.statement.block_hash, 435)};
    keep.statement.previous_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    keep.statement.accepted_btcc_cursor =
        advance.statement.accepted_btcc_cursor;
    prepared = ahead.PrepareCandidate(keep, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(ahead.AcceptVerified(*prepared, keep, true, &error));
    BOOST_REQUIRE(ahead.GetUnsealedBTCC());

    prepared = caught_up.PrepareCatchupCandidate(keep, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(caught_up.AcceptCatchupVerified(
        *prepared, keep, true, [] { return true; }, {}, &error));
    BOOST_CHECK(!caught_up.GetUnsealedBTCC());
    BOOST_CHECK(!caught_up_reconciliation);

    // H+10's target hash binds its own null carrier. Both the node that saw
    // ADVANCE(H) and the node that did not can therefore install one exact
    // KEEP(O) current winner. The chain integration must explicitly attest
    // that null-carrier proof before storage will authorize the regression.
    const auto recovery{
        MakeChainLock(880, 875, keep.statement.block_hash, 436)};
    prepared = ahead.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!ahead.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error));
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    ahead.AbandonPrepared(*prepared);

    const auto proof{MakeReconciliationProof(keep, 436)};
    BOOST_REQUIRE(proof.IsStructurallyValid());
    ahead_context.btcc_cursor_reconciliation = proof;
    prepared = ahead.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(ahead.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error));
    BOOST_CHECK(ahead_reconciliation);
    BOOST_CHECK(!ahead.GetUnsealedBTCC());

    caught_up_context.btcc_cursor_reconciliation = proof;
    prepared = caught_up.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(caught_up.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error));
    BOOST_CHECK(caught_up_reconciliation);
    BOOST_CHECK(!caught_up.GetUnsealedBTCC());

    prepared = behind.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(behind.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error));
    BOOST_CHECK(!behind_reconciliation);
    BOOST_REQUIRE(ahead.GetBest());
    BOOST_REQUIRE(caught_up.GetBest());
    BOOST_REQUIRE(behind.GetBest());
    BOOST_CHECK(*ahead.GetBest() == recovery);
    BOOST_CHECK(*caught_up.GetBest() == recovery);
    BOOST_CHECK(*behind.GetBest() == recovery);
}

BOOST_AUTO_TEST_CASE(catchup_rechecks_context_after_index_durability_hook)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(406), MakeConfig(), context};
    const auto candidate{MakeChainLock(885, 880, NonNullHash(880), 406)};
    auto prepared{store.PrepareCatchupCandidate(candidate)};
    BOOST_REQUIRE(prepared);

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptCatchupVerified(
        *prepared, candidate, true,
        [&] {
            // Model an active-tip/context change at the index-fsync seam. The
            // production handler additionally holds m_chainstate_mutex here.
            ++context.generation;
            return true;
        },
        {},
        &error));
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    BOOST_CHECK(!store.GetBest());
}

BOOST_AUTO_TEST_CASE(historical_durable_authorization_is_the_fsync_seam)
{
    const uint256 genesis{NonNullHash(407)};
    TestFinalityContext context;
    std::size_t durable_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&) {
            ++durable_writes;
            return true;
        }};
    const auto candidate{MakeChainLock(885, 880, NonNullHash(880), 407)};
    auto prepared{store.PrepareCatchupCandidate(candidate)};
    BOOST_REQUIRE(prepared);

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    bool authorization_called{false};
    BOOST_CHECK(!store.AcceptCatchupVerified(
        *prepared, candidate, true, [] { return true; },
        [&](const std::function<bool()>&,
            ChainLockFinalityError* callback_error) {
            authorization_called = true;
            BOOST_CHECK_EQUAL(durable_writes, 0U);
            if (callback_error != nullptr) {
                *callback_error = ChainLockFinalityError::CONTEXT_CHANGED;
            }
            return false;
        },
        &error));
    BOOST_CHECK(authorization_called);
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    BOOST_CHECK_EQUAL(durable_writes, 0U);
    BOOST_CHECK(!store.GetBest());

    TestFinalityContext success_context;
    ChainLockFinalityStore success_store{
        genesis, MakeConfig(), success_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&) {
            ++durable_writes;
            return true;
        }};
    prepared = success_store.PrepareCatchupCandidate(candidate);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(success_store.AcceptCatchupVerified(
        *prepared, candidate, true, [] { return true; },
        [&](const std::function<bool()>& persist_record,
            ChainLockFinalityError*) {
            BOOST_CHECK_EQUAL(durable_writes, 0U);
            const bool persisted{persist_record()};
            BOOST_CHECK_EQUAL(durable_writes, 1U);
            return persisted;
        },
        &error));
    BOOST_REQUIRE(success_store.GetBest());
    BOOST_CHECK(*success_store.GetBest() == candidate);
}

BOOST_AUTO_TEST_CASE(preseal_receipt_at_updated_anchor_rebases_as_catchup)
{
    constexpr int32_t local_best_height{865};
    constexpr int32_t receipt_anchor_height{880};
    constexpr int32_t first_carrier_height{
        receipt_anchor_height + static_cast<int32_t>(PQ_BTCC_NEVM_LAG)};
    const uint256 genesis{NonNullHash(408)};
    TestFinalityContext context;
    std::size_t archive_writes{0};
    std::size_t catchup_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {},
        [&](const FinalChainLock&) {
            ++archive_writes;
            return true;
        },
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&) {
            ++catchup_writes;
            return true;
        }};

    BOOST_REQUIRE(IsBTCCReceiptCarrierHeight(
        MakeConfig().btcc_schedule, first_carrier_height));
    const auto local{MakeChainLock(local_best_height, 864,
                                   NonNullHash(864), 408)};
    auto prepared{store.PrepareCandidate(local)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, local, true));

    // Model C=A+10 carrying the marker's exact ADVANCE T=A. The handler has
    // already authenticated the marker token and signatures before selecting
    // this CATCHUP store seam.
    auto newer_receipt{MakeChainLock(receipt_anchor_height, 875,
                                     NonNullHash(875), 409)};
    newer_receipt.statement.accepted_btcc_cursor =
        MakeCursor(880, 409);
    newer_receipt.statement.btcc_advance = BTCCAdvance::ADVANCE;
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.PreparePresealReceiptCandidate(
        newer_receipt, &error));
    BOOST_CHECK(error == ChainLockFinalityError::STALE_HEIGHT);

    prepared = store.PrepareCatchupCandidate(newer_receipt, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, newer_receipt, true, [] { return true; },
        [&](const std::function<bool()>& persist_record,
            ChainLockFinalityError*) { return persist_record(); },
        &error));
    BOOST_CHECK_EQUAL(archive_writes, 0U);
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == newer_receipt);

    TestFinalityContext archive_context;
    ChainLockFinalityStore archive_store{
        genesis, MakeConfig(), archive_context, {},
        [&](const FinalChainLock&) {
            ++archive_writes;
            return true;
        }};
    const auto later_local{
        MakeChainLock(885, 880, NonNullHash(880), 411)};
    prepared = archive_store.PreparePersistedCandidate(later_local);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(archive_store.AcceptPersistedVerified(
        *prepared, later_local, true));

    auto older_receipt{
        MakeChainLock(870, 865, NonNullHash(865), 410)};
    older_receipt.statement.accepted_btcc_cursor =
        MakeCursor(870, 410);
    older_receipt.statement.btcc_advance = BTCCAdvance::ADVANCE;
    prepared = archive_store.PreparePresealReceiptCandidate(
        older_receipt, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(archive_store.AcceptPresealReceiptVerified(
        *prepared, older_receipt, true, [] { return true; },
        [&](const std::function<bool()>& persist_record,
            ChainLockFinalityError*) { return persist_record(); },
        &error));
    BOOST_CHECK_EQUAL(archive_writes, 1U);
    BOOST_CHECK(*archive_store.GetBest() == later_local);
}

BOOST_AUTO_TEST_CASE(receipt_archive_is_verified_without_rebasing_best)
{
    const uint256 genesis{NonNullHash(42)};
    TestFinalityContext context;
    std::size_t archive_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {},
        [&](const FinalChainLock&) {
            ++archive_writes;
            return true;
        }};

    auto archived{MakeChainLock(870, 865, NonNullHash(865), 42)};
    archived.statement.accepted_btcc_cursor =
        MakeCursor(870, 42);
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;

    auto latest{MakeChainLock(875, 870, archived.statement.block_hash, 43)};
    latest.statement.previous_btcc_cursor =
        archived.statement.accepted_btcc_cursor;
    latest.statement.accepted_btcc_cursor =
        archived.statement.accepted_btcc_cursor;
    auto latest_prepared{store.PreparePersistedCandidate(latest)};
    BOOST_REQUIRE(latest_prepared);
    BOOST_REQUIRE(store.AcceptPersistedVerified(
        *latest_prepared, latest, true));

    auto archive_prepared{store.PrepareReceiptArchiveCandidate(archived)};
    BOOST_REQUIRE(archive_prepared);
    BOOST_CHECK(archive_prepared->admission ==
                ChainLockCandidateAdmission::RECEIPT_ARCHIVE);
    BOOST_REQUIRE(store.AcceptReceiptArchiveVerified(
        *archive_prepared, archived, true));
    BOOST_CHECK_EQUAL(archive_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == latest);
    BOOST_REQUIRE(store.GetByLogicalId(archived.GetLogicalId(genesis)));
}

BOOST_AUTO_TEST_CASE(live_predecessor_binds_the_exact_btcc_cursor)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(41), MakeConfig(), context};
    const auto first{MakeChainLock(865, 864, NonNullHash(864), 41)};
    auto prepared{store.PrepareCandidate(first)};
    BOOST_REQUIRE(prepared);
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptPersistedVerified(*prepared, first, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, first, true));

    auto mismatch{MakeChainLock(
        870, first.statement.height, first.statement.block_hash, 42)};
    mismatch.statement.previous_btcc_cursor = MakeCursor(860, 2);
    mismatch.statement.accepted_btcc_cursor = mismatch.statement.previous_btcc_cursor;
    BOOST_CHECK(!store.PrepareCandidate(mismatch, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);
}

BOOST_AUTO_TEST_SUITE_END()
