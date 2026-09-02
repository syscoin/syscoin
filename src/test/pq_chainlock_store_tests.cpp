// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/pq_chainlock_store.h>

#include <test/pq_test_util.h>
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

RosterBeaconSeed ReadySeed(uint32_t epoch)
{
    RosterBeaconSeed seed;
    seed.state = RosterBeaconState::READY;
    seed.epoch = epoch;
    seed.anchor_cursor = BTCCursor{
        10'000 + static_cast<int32_t>(epoch),
        NonNullHash(100'000 + epoch), NonNullHash(200'000 + epoch)};
    seed.anchor_btc_height = 800'000 + static_cast<int32_t>(epoch);
    seed.future_btc_hash = NonNullHash(300'000 + epoch);
    return seed;
}

RosterBeaconWindow ReadyWindow(int32_t height)
{
    RosterBeaconWindow window;
    const auto schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    const auto active{ActiveEpochsAtHeight(*schedule, height)};
    BOOST_REQUIRE(active);
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        window.active.seeds[slot] = ReadySeed((*active)[slot].epoch);
    }
    window.next.epoch = active->back().epoch + 1;
    return window;
}

RosterBeaconWindow InitializationWindow(int32_t height)
{
    RosterBeaconWindow window;
    const auto schedule{MakeChainLockScheduleConfig(0)};
    BOOST_REQUIRE(schedule);
    const auto active{ActiveEpochsAtHeight(*schedule, height)};
    BOOST_REQUIRE(active);
    const auto shared{ReadySeed(active->front().epoch)};
    for (std::size_t slot{0}; slot < ACTIVE_QUORUMS; ++slot) {
        auto seed{shared};
        seed.epoch = (*active)[slot].epoch;
        window.active.seeds[slot] = std::move(seed);
    }
    window.next.epoch = active->back().epoch + 1;
    return window;
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
    chainlock.statement.roster_transition =
        RosterAuthorizationTransitionKind::KEEP;
    chainlock.statement.roster_authorization_base = {
        previous_height, previous_hash, NonNullHash(39'000 + salt)};
    chainlock.statement.roster_beacons = ReadyWindow(height);
    chainlock.statement.roster_authorization_state_hash =
        NonNullHash(40'000 + salt);
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
    config.activation_predecessor_height = 864;
    config.seen_logical_capacity = cache_capacity;
    config.seen_witness_capacity = cache_capacity;
    config.rejected_witness_capacity = cache_capacity;
    config.recent_chainlocks_capacity = recent_capacity;
    return config;
}

PreparedChainLockContextPtr MakeVerificationContext(
    const uint256& genesis_hash,
    const ChainLockFinalityStoreConfig& config,
    const FinalChainLock& chainlock)
{
    return ChainLockStoreTestContextFactory::Create(
        genesis_hash, config.chainlock_schedule, chainlock.statement);
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

BOOST_AUTO_TEST_CASE(best_record_view_shares_witness_and_tracks_store_revision)
{
    const uint256 genesis{NonNullHash(101)};
    TestFinalityContext context;
    ChainLockFinalityStore store{genesis, MakeConfig(), context};
    BOOST_CHECK(!store.GetBestRecord());
    const auto empty_observation{store.ObserveState()};
    BOOST_CHECK_EQUAL(empty_observation.state_revision, 0U);
    BOOST_CHECK(!empty_observation.best);

    const auto first{MakeChainLock(865, 864, NonNullHash(864), 101)};
    auto prepared{store.PrepareCandidate(first)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, first, true));

    const auto certificate{store.GetBest()};
    const auto first_view{store.GetBestRecord()};
    BOOST_REQUIRE(certificate);
    BOOST_REQUIRE(first_view);
    BOOST_CHECK_EQUAL(first_view->state_revision, 1U);
    BOOST_CHECK(first_view->metadata.logical_id ==
                first.GetLogicalId(genesis));
    BOOST_CHECK(first_view->metadata.witness_id ==
                first.GetWitnessId(genesis));
    BOOST_CHECK(first_view->metadata.statement == first.statement);
    BOOST_CHECK(first_view->certificate == certificate);
    const auto first_observation{store.ObserveState()};
    BOOST_CHECK_EQUAL(first_observation.state_revision, 1U);
    BOOST_REQUIRE(first_observation.best);
    BOOST_CHECK(*first_observation.best == first_view->metadata);

    const auto second{MakeChainLock(
        870, first.statement.height, first.statement.block_hash, 102)};
    prepared = store.PrepareCandidate(second);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, second, true));

    const auto second_view{store.GetBestRecord()};
    BOOST_REQUIRE(second_view);
    BOOST_CHECK_EQUAL(second_view->state_revision, 2U);
    BOOST_CHECK(second_view->metadata.statement == second.statement);
    const auto second_observation{store.ObserveState()};
    BOOST_CHECK_EQUAL(second_observation.state_revision, 2U);
    BOOST_REQUIRE(second_observation.best);
    BOOST_CHECK(*second_observation.best == second_view->metadata);
    BOOST_CHECK(first_view->certificate == certificate);
    BOOST_CHECK(*first_view->certificate == first);
}

BOOST_AUTO_TEST_CASE(verified_authorization_base_is_exact_and_not_finality)
{
    const uint256 genesis{NonNullHash(109)};
    const auto config{MakeConfig(/*cache_capacity=*/8,
                                 /*recent_capacity=*/2)};
    TestFinalityContext context;
    ChainLockFinalityStore store{genesis, config, context};
    const auto first{MakeChainLock(865, 864, NonNullHash(864), 109)};
    const auto first_context{MakeVerificationContext(genesis, config, first)};
    BOOST_REQUIRE(first_context);

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_REQUIRE(store.AcceptVerifiedRosterAuthorizationBase(
        first, /*signatures_valid=*/true, first_context, &error));
    BOOST_CHECK(error == ChainLockFinalityError::NONE);
    BOOST_CHECK(!store.GetBest());
    BOOST_CHECK(!store.GetByHeight(first.statement.height));
    BOOST_CHECK(!store.GetByLogicalId(first.GetLogicalId(genesis)));
    BOOST_CHECK(store.AlreadyHaveWitness(first.GetWitnessId(genesis)));

    const RosterAuthorizationBaseIdentity identity{
        first.statement.height, first.statement.block_hash,
        first.GetLogicalId(genesis)};
    const auto retained{store.GetVerifiedRosterAuthorizationBase(identity)};
    BOOST_REQUIRE(retained);
    BOOST_CHECK(retained->metadata.AuthorizationBase() == identity);
    BOOST_CHECK(retained->certificate && *retained->certificate == first);
    BOOST_CHECK(retained->verification_context == first_context);

    auto wrong{identity};
    wrong.block_hash = NonNullHash(110);
    BOOST_CHECK(!store.GetVerifiedRosterAuthorizationBase(wrong));
    wrong = identity;
    wrong.logical_id = NonNullHash(111);
    BOOST_CHECK(!store.GetVerifiedRosterAuthorizationBase(wrong));

    // A different accepted winner at the same height must not shadow the
    // exact authorization-only certificate named by logical ID.
    const auto same_height_winner{
        MakeChainLock(865, 864, NonNullHash(864), 112)};
    const auto prepared{store.PrepareCandidate(same_height_winner, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(
        *prepared, same_height_winner, true, &error,
        MakeVerificationContext(genesis, config, same_height_winner)));
    BOOST_REQUIRE(store.GetVerifiedRosterAuthorizationBase(identity));
    const RosterAuthorizationBaseIdentity winner_identity{
        same_height_winner.statement.height,
        same_height_winner.statement.block_hash,
        same_height_winner.GetLogicalId(genesis)};
    BOOST_REQUIRE(
        store.GetVerifiedRosterAuthorizationBase(winner_identity));

    auto second{MakeChainLock(870, 865, first.statement.block_hash, 110)};
    auto third{MakeChainLock(875, 870, second.statement.block_hash, 111)};
    BOOST_REQUIRE(store.AcceptVerifiedRosterAuthorizationBase(
        second, true, MakeVerificationContext(genesis, config, second)));
    BOOST_REQUIRE(store.AcceptVerifiedRosterAuthorizationBase(
        third, true, MakeVerificationContext(genesis, config, third)));
    BOOST_CHECK_EQUAL(store.AuthorizationBaseSizeForTesting(), 4U);
    BOOST_CHECK(store.GetVerifiedRosterAuthorizationBase(identity));
}

BOOST_AUTO_TEST_CASE(persisted_authorization_base_requires_trusted_context)
{
    const uint256 genesis{NonNullHash(113)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    ChainLockFinalityStore store{genesis, config, context};
    const auto base{MakeChainLock(865, 864, NonNullHash(864), 113)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    BOOST_CHECK(!store.AcceptPersistedRosterAuthorizationBase(
        base, /*signatures_valid=*/true,
        MakeVerificationContext(genesis, config, base), &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_PREPARATION_TOKEN);

    const auto trusted{
        ChainLockStoreTestContextFactory::CreateTrustedPersistence(
            genesis, config.chainlock_schedule, base.statement)};
    BOOST_REQUIRE(trusted);
    BOOST_REQUIRE(store.AcceptPersistedRosterAuthorizationBase(
        base, /*signatures_valid=*/true, trusted, &error));
    BOOST_CHECK(error == ChainLockFinalityError::NONE);
    BOOST_CHECK(!store.GetBest());

    const RosterAuthorizationBaseIdentity identity{
        base.statement.height, base.statement.block_hash,
        base.GetLogicalId(genesis)};
    const auto retained{store.GetVerifiedRosterAuthorizationBase(identity)};
    BOOST_REQUIRE(retained);
    BOOST_CHECK(retained->certificate && *retained->certificate == base);
    BOOST_CHECK(retained->verification_context->Authorization().admission ==
                RosterAuthorizationAdmission::TRUSTED_PERSISTENCE);
}

BOOST_AUTO_TEST_CASE(activation_height_is_not_finality_before_first_winner)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(1), MakeConfig(), context};
    const uint256 candidate{NonNullHash(859)};

    BOOST_CHECK(!store.HasChainLock(/*height=*/859, candidate));
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/true));
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/false));

    context.accepted_branch.emplace(859, NonNullHash(999));
    BOOST_CHECK(!store.HasChainLock(/*height=*/859, candidate));
    BOOST_CHECK(!store.HasConflictingChainLock(
        /*height=*/859, candidate, /*unknown_is_conflict=*/true));

    const auto first{MakeChainLock(865, 864, NonNullHash(864), 201)};
    auto prepared{store.PrepareCandidate(first)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, first, true));

    context.accepted_branch[859] = candidate;
    BOOST_CHECK(store.HasChainLock(/*height=*/859, candidate));
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

BOOST_AUTO_TEST_CASE(invalid_first_witness_does_not_pin_activation_hash)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(202), MakeConfig(), context};
    const uint256 predecessor_a{NonNullHash(8641)};
    const uint256 predecessor_b{NonNullHash(8642)};
    const auto invalid{MakeChainLock(865, 864, predecessor_a, 202)};

    auto prepared{store.PrepareCandidate(invalid)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!prepared->has_local_chainlock);
    BOOST_CHECK(prepared->predecessor.block_hash == predecessor_a);
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptVerified(*prepared, invalid, false, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_SIGNATURES);
    BOOST_CHECK(!store.GetBest());

    const auto winner{MakeChainLock(865, 864, predecessor_b, 203)};
    prepared = store.PrepareCandidate(winner, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(prepared->predecessor.block_hash == predecessor_b);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, winner, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::NONE);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == winner);
}

BOOST_AUTO_TEST_CASE(first_seen_candidate_does_not_pin_activation_hash)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(208), MakeConfig(), context};
    const auto branch_a{
        MakeChainLock(865, 864, NonNullHash(8646), 208)};
    const auto branch_b{
        MakeChainLock(865, 864, NonNullHash(8647), 209)};

    auto prepared_a{store.PrepareCandidate(branch_a)};
    auto prepared_b{store.PrepareCandidate(branch_b)};
    BOOST_REQUIRE(prepared_a);
    BOOST_REQUIRE(prepared_b);
    BOOST_CHECK(prepared_a->predecessor.block_hash !=
                prepared_b->predecessor.block_hash);
    BOOST_REQUIRE(store.AcceptVerified(*prepared_b, branch_b, true));

    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptVerified(*prepared_a, branch_a, true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    BOOST_CHECK(*store.GetBest() == branch_b);
}

BOOST_AUTO_TEST_CASE(first_predecessor_must_be_proven_by_candidate_context)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(204), MakeConfig(), context};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    const auto rejected{
        MakeChainLock(865, 864, NonNullHash(8643), 204)};

    context.descendant = false;
    BOOST_CHECK(!store.PrepareCandidate(rejected, &error));
    BOOST_CHECK(error == ChainLockFinalityError::NOT_PREDECESSOR_DESCENDANT);
    BOOST_CHECK(!store.GetBest());

    context.descendant = true;
    const auto winner{MakeChainLock(865, 864, NonNullHash(8644), 205)};
    auto prepared{store.PrepareCandidate(winner, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerified(*prepared, winner, true, &error));
    BOOST_CHECK(*store.GetBest() == winner);
}

BOOST_AUTO_TEST_CASE(first_predecessor_requires_nonnull_hash_and_null_cursor)
{
    TestFinalityContext context;
    ChainLockFinalityStore store{NonNullHash(206), MakeConfig(), context};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    const auto null_hash{MakeChainLock(865, 864, {}, 206)};
    BOOST_CHECK(!store.PrepareCandidate(null_hash, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_CHAINLOCK);

    auto cursor_mismatch{
        MakeChainLock(865, 864, NonNullHash(8645), 207)};
    cursor_mismatch.statement.previous_btcc_cursor = MakeCursor(860, 207);
    cursor_mismatch.statement.accepted_btcc_cursor =
        cursor_mismatch.statement.previous_btcc_cursor;
    BOOST_REQUIRE(cursor_mismatch.IsStructurallyValid());
    BOOST_CHECK(!store.PrepareCandidate(cursor_mismatch, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);
    BOOST_CHECK(!store.GetBest());
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
    const uint256 genesis{NonNullHash(30)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    bool allow_persistence{false};
    std::size_t callback_count{0};
    ChainLockFinalityStore store{
        genesis, config, context,
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++callback_count;
            return allow_persistence;
        }};
    const auto chainlock{MakeChainLock(865, 864, NonNullHash(864), 30)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};

    auto prepared{store.PrepareCandidate(chainlock, &error)};
    BOOST_REQUIRE(prepared);
    const auto verification_context{
        MakeVerificationContext(genesis, config, chainlock)};
    BOOST_CHECK(!store.AcceptVerified(
        *prepared, chainlock, true, &error, verification_context));
    BOOST_CHECK(error == ChainLockFinalityError::PERSISTENCE_FAILURE);
    BOOST_CHECK(!store.GetBest());
    BOOST_CHECK(!store.GetBestRecord());
    BOOST_CHECK_EQUAL(store.RecentSizeForTesting(), 0U);
    BOOST_CHECK_EQUAL(callback_count, 1U);

    store.AbandonPrepared(*prepared);
    allow_persistence = true;
    prepared = store.PrepareCandidate(chainlock, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(store.AcceptVerified(
        *prepared, chainlock, true, &error, verification_context));
    BOOST_CHECK(store.GetBest() && *store.GetBest() == chainlock);
    BOOST_REQUIRE(store.GetBestRecord());
    BOOST_CHECK_EQUAL(store.GetBestRecord()->state_revision, 1U);
    BOOST_CHECK_EQUAL(callback_count, 2U);
}

BOOST_AUTO_TEST_CASE(reset_capability_crosses_only_the_fully_verified_store_seam)
{
    const uint256 genesis{NonNullHash(31)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t ordinary_callbacks{0};
    std::size_t reset_callbacks{0};
    ChainLockFinalityStore store{
        genesis, config, context,
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++ordinary_callbacks;
            return true;
        },
        {}, {}, {}, {},
        [&](const FinalChainLock& chainlock,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation,
            const ReceiptArchiveRosterAuthorization* authorization,
            const PreparedChainLockContextPtr& verification_context,
            const VerifiedRecoveryResetPersistenceCapability&) {
            ++reset_callbacks;
            BOOST_CHECK(chainlock.statement.roster_transition ==
                        RosterAuthorizationTransitionKind::INITIALIZE);
            BOOST_CHECK(!reconciliation);
            BOOST_CHECK(authorization == nullptr);
            BOOST_REQUIRE(verification_context);
            BOOST_CHECK(verification_context->Statement() ==
                        chainlock.statement);
            return true;
        }};

    auto rejected{MakeChainLock(865, 864, NonNullHash(864), 31)};
    rejected.statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    rejected.statement.roster_authorization_base = {};
    rejected.statement.roster_beacons = InitializationWindow(865);
    auto prepared{store.PrepareCandidate(rejected)};
    BOOST_REQUIRE(prepared);
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptVerified(
        *prepared, rejected, /*signatures_valid=*/false, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_SIGNATURES);
    BOOST_CHECK_EQUAL(reset_callbacks, 0U);

    auto accepted{MakeChainLock(865, 864, NonNullHash(864), 32)};
    accepted.statement.roster_transition =
        RosterAuthorizationTransitionKind::INITIALIZE;
    accepted.statement.roster_authorization_base = {};
    accepted.statement.roster_beacons = InitializationWindow(865);
    prepared = store.PrepareCandidate(accepted, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!store.AcceptVerified(
        *prepared, accepted, /*signatures_valid=*/true, &error));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    BOOST_CHECK_EQUAL(reset_callbacks, 0U);
    store.AbandonPrepared(*prepared);

    prepared = store.PrepareCandidate(accepted, &error);
    BOOST_REQUIRE(prepared);
    const auto verification_context{
        MakeVerificationContext(genesis, config, accepted)};
    BOOST_REQUIRE(store.AcceptVerified(
        *prepared, accepted, /*signatures_valid=*/true, &error,
        verification_context));
    BOOST_CHECK_EQUAL(reset_callbacks, 1U);
    BOOST_CHECK_EQUAL(ordinary_callbacks, 0U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == accepted);
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
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
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
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t catchup_writes{0};
    std::size_t catchup_pre_durable_calls{0};
    std::size_t null_covering_authorizations{0};
    bool require_covering_authorization{false};
    std::optional<ReceiptArchiveRosterAuthorization>
        observed_covering_authorization;
    ChainLockFinalityStore store{
        genesis, config, context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization* authorization,
            const PreparedChainLockContextPtr&) {
            ++catchup_writes;
            if (authorization == nullptr) {
                ++null_covering_authorizations;
                return !require_covering_authorization;
            }
            observed_covering_authorization = *authorization;
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
        *prepared, first_rebase, true,
        [&] {
            ++catchup_pre_durable_calls;
            return true;
        },
        {}, &error, nullptr,
        MakeVerificationContext(genesis, config, first_rebase)));
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_CHECK_EQUAL(catchup_pre_durable_calls, 1U);
    BOOST_CHECK_EQUAL(null_covering_authorizations, 1U);
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
    const ReceiptArchiveRosterAuthorization authorization{
        FinalChainLockRecordMetadata{
            first_rebase.GetLogicalId(genesis),
            first_rebase.GetWitnessId(genesis), first_rebase.statement},
        exact.GetLogicalId(genesis), exact.GetWitnessId(genesis),
        FinalChainLockRecordMetadata{
            local.GetLogicalId(genesis), local.GetWitnessId(genesis),
            local.statement}};
    BOOST_REQUIRE(authorization.IsInternallyConsistent(genesis));

    auto malformed_authorization{authorization};
    malformed_authorization.owner.logical_id = NonNullHash(405);
    prepared = store.PrepareCatchupCandidate(second_rebase, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!store.AcceptCatchupVerified(
        *prepared, second_rebase, true,
        [&] {
            ++catchup_pre_durable_calls;
            return true;
        },
        {}, &error, &malformed_authorization,
        MakeVerificationContext(genesis, config, second_rebase)));
    BOOST_CHECK(error == ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_CHECK_EQUAL(catchup_pre_durable_calls, 1U);
    BOOST_CHECK(*store.GetBest() == exact);
    store.AbandonPrepared(*prepared);

    require_covering_authorization = true;
    prepared = store.PrepareCatchupCandidate(second_rebase, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!store.AcceptCatchupVerified(
        *prepared, second_rebase, true,
        [&] {
            ++catchup_pre_durable_calls;
            return true;
        },
        {}, &error, nullptr,
        MakeVerificationContext(genesis, config, second_rebase)));
    BOOST_CHECK(error == ChainLockFinalityError::PERSISTENCE_FAILURE);
    BOOST_CHECK_EQUAL(catchup_writes, 2U);
    BOOST_CHECK_EQUAL(catchup_pre_durable_calls, 2U);
    BOOST_CHECK_EQUAL(null_covering_authorizations, 2U);
    BOOST_CHECK(*store.GetBest() == exact);
    store.AbandonPrepared(*prepared);

    prepared = store.PrepareCatchupCandidate(second_rebase, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, second_rebase, true,
        [&] {
            ++catchup_pre_durable_calls;
            return true;
        },
        {}, &error, &authorization,
        MakeVerificationContext(genesis, config, second_rebase)));
    BOOST_CHECK_EQUAL(catchup_writes, 3U);
    BOOST_CHECK_EQUAL(catchup_pre_durable_calls, 3U);
    BOOST_REQUIRE(observed_covering_authorization);
    BOOST_CHECK(*observed_covering_authorization == authorization);
    BOOST_CHECK(*store.GetBest() == second_rebase);

    const auto predecessor_before_local{
        MakeChainLock(905, 900, NonNullHash(900), 405)};
    BOOST_CHECK(!store.PrepareCatchupCandidate(
        predecessor_before_local, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);
}

BOOST_AUTO_TEST_CASE(
    first_winner_can_be_current_catchup_after_multiple_missed_rounds)
{
    const uint256 genesis{NonNullHash(406)};
    const auto config{MakeConfig()};
    const auto window{CurrentChainLockSigningWindow(
        config.chainlock_schedule, config.activation_predecessor_height,
        /*tip_height=*/885)};
    BOOST_REQUIRE(window);
    // Targets 865, 870, and 875 elapsed without a durable certificate. The
    // live scheduler must move to target 880 instead of waiting on 865.
    BOOST_CHECK_EQUAL(window->target_height, 880);
    BOOST_CHECK_EQUAL(window->declared_predecessor_height, 875);

    TestFinalityContext context;
    std::size_t live_writes{0};
    std::size_t catchup_writes{0};
    std::size_t pre_durable_calls{0};
    ChainLockFinalityStore store{
        genesis, config, context,
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++live_writes;
            return true;
        },
        {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
            ++catchup_writes;
            return true;
        }};

    const auto recovered{MakeChainLock(
        window->target_height, window->declared_predecessor_height,
        NonNullHash(window->declared_predecessor_height), 406)};
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.PrepareCandidate(recovered, &error));
    BOOST_CHECK(error == ChainLockFinalityError::PREDECESSOR_MISMATCH);

    auto prepared{store.PrepareCatchupCandidate(recovered, &error)};
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(!prepared->has_local_chainlock);
    BOOST_CHECK(prepared->admission == ChainLockCandidateAdmission::CATCHUP);
    BOOST_CHECK(context.last_admission == ChainLockCandidateAdmission::CATCHUP);
    BOOST_REQUIRE(store.AcceptCatchupVerified(
        *prepared, recovered, /*signatures_valid=*/true,
        [&] {
            ++pre_durable_calls;
            return true;
        },
        {}, &error, nullptr,
        MakeVerificationContext(genesis, config, recovered)));
    BOOST_CHECK(error == ChainLockFinalityError::NONE);
    BOOST_CHECK_EQUAL(pre_durable_calls, 1U);
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_CHECK_EQUAL(live_writes, 0U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == recovered);

    // Once the gap is durably rebased, the immediately following target uses
    // the recovered certificate as its exact predecessor and returns to LIVE.
    const auto next_height{NextEligibleChainLockTargetHeight(
        config.chainlock_schedule, recovered.statement.height)};
    BOOST_REQUIRE(next_height);
    const auto next{MakeChainLock(
        *next_height, recovered.statement.height,
        recovered.statement.block_hash, 407)};
    prepared = store.PrepareCandidate(next, &error);
    BOOST_REQUIRE(prepared);
    BOOST_CHECK(prepared->has_local_chainlock);
    BOOST_CHECK(prepared->predecessor.height == recovered.statement.height);
    BOOST_CHECK(prepared->predecessor.block_hash ==
                recovered.statement.block_hash);
    BOOST_CHECK(prepared->admission == ChainLockCandidateAdmission::LIVE);
    BOOST_CHECK(context.last_admission == ChainLockCandidateAdmission::LIVE);
    BOOST_REQUIRE(store.AcceptVerified(
        *prepared, next, /*signatures_valid=*/true, &error,
        MakeVerificationContext(genesis, config, next)));
    BOOST_CHECK(error == ChainLockFinalityError::NONE);
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_CHECK_EQUAL(live_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == next);
}

BOOST_AUTO_TEST_CASE(
    current_catchup_may_reconcile_a_cursor_view_but_never_regress_durable_state)
{
    const uint256 genesis{NonNullHash(420)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t catchup_writes{0};
    ChainLockFinalityStore store{
        genesis, config, context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
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
        *prepared, recovery, true, [] { return true; }, {}, &error,
        nullptr, MakeVerificationContext(genesis, config, recovery)));
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == recovery);
}

BOOST_AUTO_TEST_CASE(
    candidate_bound_null_carrier_reconciles_heterogeneous_durable_views)
{
    const uint256 genesis{NonNullHash(433)};
    const auto config{MakeConfig()};
    TestFinalityContext ahead_context;
    TestFinalityContext caught_up_context;
    TestFinalityContext behind_context;
    bool ahead_reconciliation{false};
    bool caught_up_reconciliation{false};
    bool behind_reconciliation{true};
    ChainLockFinalityStore ahead{
        genesis, config, ahead_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
            ahead_reconciliation = reconciliation.has_value();
            return true;
        }};
    ChainLockFinalityStore caught_up{
        genesis, config, caught_up_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
            caught_up_reconciliation = reconciliation.has_value();
            return true;
        }};
    ChainLockFinalityStore behind{
        genesis, config, behind_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>& reconciliation,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
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
        *prepared, keep, true, [] { return true; }, {}, &error, nullptr,
        MakeVerificationContext(genesis, config, keep)));
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
        *prepared, recovery, true, [] { return true; }, {}, &error,
        nullptr, MakeVerificationContext(genesis, config, recovery)));
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    ahead.AbandonPrepared(*prepared);

    const auto proof{MakeReconciliationProof(keep, 436)};
    BOOST_REQUIRE(proof.IsStructurallyValid());
    ahead_context.btcc_cursor_reconciliation = proof;
    prepared = ahead.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(ahead.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error,
        nullptr, MakeVerificationContext(genesis, config, recovery)));
    BOOST_CHECK(ahead_reconciliation);
    BOOST_CHECK(!ahead.GetUnsealedBTCC());

    caught_up_context.btcc_cursor_reconciliation = proof;
    prepared = caught_up.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(caught_up.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error,
        nullptr, MakeVerificationContext(genesis, config, recovery)));
    BOOST_CHECK(caught_up_reconciliation);
    BOOST_CHECK(!caught_up.GetUnsealedBTCC());

    prepared = behind.PrepareCatchupCandidate(recovery, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(behind.AcceptCatchupVerified(
        *prepared, recovery, true, [] { return true; }, {}, &error,
        nullptr, MakeVerificationContext(genesis, config, recovery)));
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
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t durable_writes{0};
    ChainLockFinalityStore store{
        genesis, config, context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
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
        &error, nullptr,
        MakeVerificationContext(genesis, config, candidate)));
    BOOST_CHECK(authorization_called);
    BOOST_CHECK(error == ChainLockFinalityError::CONTEXT_CHANGED);
    BOOST_CHECK_EQUAL(durable_writes, 0U);
    BOOST_CHECK(!store.GetBest());

    TestFinalityContext success_context;
    ChainLockFinalityStore success_store{
        genesis, config, success_context, {}, {},
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
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
        &error, nullptr,
        MakeVerificationContext(genesis, config, candidate)));
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
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t archive_writes{0};
    std::size_t catchup_writes{0};
    ChainLockFinalityStore store{
        genesis, config, context, {},
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++archive_writes;
            return true;
        },
        [&](const FinalChainLock&,
            const std::optional<BTCCCursorReconciliationProof>&,
            const ReceiptArchiveRosterAuthorization*,
            const PreparedChainLockContextPtr&) {
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
        &error, nullptr,
        MakeVerificationContext(genesis, config, newer_receipt)));
    BOOST_CHECK_EQUAL(archive_writes, 0U);
    BOOST_CHECK_EQUAL(catchup_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == newer_receipt);

    TestFinalityContext archive_context;
    ChainLockFinalityStore archive_store{
        genesis, config, archive_context, {}, {}, {},
        [&](const FinalChainLock&,
            const ReceiptArchiveRosterAuthorization&,
            const PreparedChainLockContextPtr&) {
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
    const auto authorization_predecessor{MakeChainLock(
        865, config.activation_predecessor_height,
        NonNullHash(config.activation_predecessor_height), 409)};
    const ReceiptArchiveRosterAuthorization authorization{
        FinalChainLockRecordMetadata{
            later_local.GetLogicalId(genesis),
            later_local.GetWitnessId(genesis), later_local.statement},
        later_local.GetLogicalId(genesis),
        later_local.GetWitnessId(genesis),
        FinalChainLockRecordMetadata{
            authorization_predecessor.GetLogicalId(genesis),
            authorization_predecessor.GetWitnessId(genesis),
            authorization_predecessor.statement}};
    BOOST_REQUIRE(authorization.IsInternallyConsistent(genesis));
    prepared = archive_store.PreparePresealReceiptCandidate(
        older_receipt, &error);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(archive_store.AcceptPresealReceiptVerified(
        *prepared, older_receipt, true, [] { return true; },
        [&](const std::function<bool()>& persist_record,
            ChainLockFinalityError*) { return persist_record(); },
        &error,
        MakeVerificationContext(genesis, config, older_receipt),
        &authorization));
    BOOST_CHECK_EQUAL(archive_writes, 1U);
    BOOST_CHECK(*archive_store.GetBest() == later_local);
}

BOOST_AUTO_TEST_CASE(receipt_archive_is_verified_without_rebasing_best)
{
    const uint256 genesis{NonNullHash(42)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t archive_writes{0};
    ChainLockFinalityStore store{
        genesis, config, context, {}, {}, {},
        [&](const FinalChainLock&,
            const ReceiptArchiveRosterAuthorization&,
            const PreparedChainLockContextPtr&) {
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
    const auto best_before_archive{store.GetBestRecord()};
    BOOST_REQUIRE(best_before_archive);
    BOOST_CHECK_EQUAL(best_before_archive->state_revision, 1U);
    const auto observed_before_archive{store.ObserveState()};
    BOOST_REQUIRE(observed_before_archive.best);
    BOOST_CHECK_EQUAL(observed_before_archive.state_revision, 1U);
    BOOST_CHECK(*observed_before_archive.best ==
                best_before_archive->metadata);

    auto archive_prepared{store.PrepareReceiptArchiveCandidate(archived)};
    BOOST_REQUIRE(archive_prepared);
    BOOST_CHECK(archive_prepared->admission ==
                ChainLockCandidateAdmission::RECEIPT_ARCHIVE);
    const auto authorization_predecessor{MakeChainLock(
        865, MakeConfig().activation_predecessor_height,
        NonNullHash(MakeConfig().activation_predecessor_height), 41)};
    const ReceiptArchiveRosterAuthorization authorization{
        FinalChainLockRecordMetadata{
            latest.GetLogicalId(genesis), latest.GetWitnessId(genesis),
            latest.statement},
        latest.GetLogicalId(genesis), latest.GetWitnessId(genesis),
        FinalChainLockRecordMetadata{
            authorization_predecessor.GetLogicalId(genesis),
            authorization_predecessor.GetWitnessId(genesis),
            authorization_predecessor.statement}};
    BOOST_REQUIRE(store.AcceptReceiptArchiveVerified(
        *archive_prepared, archived, true, authorization, {}, nullptr,
        MakeVerificationContext(genesis, config, archived)));
    BOOST_CHECK_EQUAL(archive_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == latest);
    const auto best_after_archive{store.GetBestRecord()};
    BOOST_REQUIRE(best_after_archive);
    BOOST_CHECK_EQUAL(best_after_archive->state_revision, 2U);
    BOOST_CHECK(best_after_archive->metadata ==
                best_before_archive->metadata);
    BOOST_CHECK(best_after_archive->certificate ==
                best_before_archive->certificate);
    const auto observed_after_archive{store.ObserveState()};
    BOOST_REQUIRE(observed_after_archive.best);
    BOOST_CHECK_EQUAL(observed_after_archive.state_revision, 2U);
    BOOST_CHECK(*observed_after_archive.best ==
                best_before_archive->metadata);
    BOOST_REQUIRE(store.GetByLogicalId(archived.GetLogicalId(genesis)));
}

BOOST_AUTO_TEST_CASE(
    trusted_unsealed_restore_is_distinct_from_network_archive_admission)
{
    const uint256 genesis{NonNullHash(421)};
    TestFinalityContext context;
    std::size_t archive_writes{0};
    ChainLockFinalityStore store{
        genesis, MakeConfig(), context, {},
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++archive_writes;
            return true;
        }};

    auto archived{MakeChainLock(870, 865, NonNullHash(865), 421)};
    archived.statement.accepted_btcc_cursor = MakeCursor(870, 421);
    archived.statement.btcc_advance = BTCCAdvance::ADVANCE;
    auto latest{MakeChainLock(
        875, 870, archived.statement.block_hash, 422)};
    latest.statement.previous_btcc_cursor =
        archived.statement.accepted_btcc_cursor;
    latest.statement.accepted_btcc_cursor =
        archived.statement.accepted_btcc_cursor;

    auto prepared{store.PreparePersistedCandidate(latest)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptPersistedVerified(*prepared, latest, true));

    auto network{store.PrepareReceiptArchiveCandidate(archived)};
    BOOST_REQUIRE(network);
    BOOST_CHECK(network->admission ==
                ChainLockCandidateAdmission::RECEIPT_ARCHIVE);
    ChainLockFinalityError error{ChainLockFinalityError::NONE};
    BOOST_CHECK(!store.AcceptTrustedUnsealedVerified(
        *network, archived, true, &error));
    BOOST_CHECK(error ==
                ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    store.AbandonPrepared(*network);

    auto trusted{store.PrepareTrustedUnsealedCandidate(archived, &error)};
    BOOST_REQUIRE(trusted);
    BOOST_CHECK(trusted->admission == ChainLockCandidateAdmission::
                                            TRUSTED_UNSEALED_PERSISTENCE);
    BOOST_CHECK(context.last_admission == ChainLockCandidateAdmission::
                                               TRUSTED_UNSEALED_PERSISTENCE);
    BOOST_CHECK(!store.AcceptVerified(*trusted, archived, true, &error));
    BOOST_CHECK(error ==
                ChainLockFinalityError::INVALID_PREPARATION_TOKEN);
    BOOST_REQUIRE(store.AcceptTrustedUnsealedVerified(
        *trusted, archived, true, &error));
    BOOST_CHECK_EQUAL(archive_writes, 0U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == latest);
    BOOST_REQUIRE(store.GetUnsealedBTCC());
    BOOST_CHECK(*store.GetUnsealedBTCC() == archived);
}

BOOST_AUTO_TEST_CASE(covered_receipt_gap_uses_dedicated_durable_callback)
{
    const uint256 genesis{NonNullHash(420)};
    const auto config{MakeConfig()};
    TestFinalityContext context;
    std::size_t ordinary_writes{0};
    std::size_t covering_writes{0};
    ChainLockFinalityStore store{
        genesis, config, context,
        [&](const FinalChainLock&,
            const PreparedChainLockContextPtr&) {
            ++ordinary_writes;
            return true;
        },
        {}, {}, {},
        [&](const FinalChainLock&,
            const ReceiptArchiveRosterAuthorization&,
            const PreparedChainLockContextPtr&) {
            ++covering_writes;
            return true;
        }};

    const auto predecessor{MakeChainLock(
        865, MakeConfig().activation_predecessor_height,
        NonNullHash(MakeConfig().activation_predecessor_height), 420)};
    const auto owner{MakeChainLock(
        875, 870, NonNullHash(870), 421)};
    auto prepared{store.PreparePersistedCandidate(owner)};
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptPersistedVerified(*prepared, owner, true));

    const ReceiptArchiveRosterAuthorization authorization{
        FinalChainLockRecordMetadata{
            owner.GetLogicalId(genesis), owner.GetWitnessId(genesis),
            owner.statement},
        owner.GetLogicalId(genesis), owner.GetWitnessId(genesis),
        FinalChainLockRecordMetadata{
            predecessor.GetLogicalId(genesis),
            predecessor.GetWitnessId(genesis), predecessor.statement}};
    BOOST_REQUIRE(authorization.IsInternallyConsistent(genesis));

    const auto successor{MakeChainLock(
        880, owner.statement.height, owner.statement.block_hash, 422)};
    prepared = store.PrepareCandidate(successor);
    BOOST_REQUIRE(prepared);
    BOOST_REQUIRE(store.AcceptVerifiedCoveringReceiptArchive(
        *prepared, successor, true, authorization, nullptr,
        MakeVerificationContext(genesis, config, successor)));
    BOOST_CHECK_EQUAL(ordinary_writes, 0U);
    BOOST_CHECK_EQUAL(covering_writes, 1U);
    BOOST_REQUIRE(store.GetBest());
    BOOST_CHECK(*store.GetBest() == successor);
}

BOOST_AUTO_TEST_CASE(validated_record_metadata_checks_precomputed_identity)
{
    const uint256 genesis{NonNullHash(43)};
    const auto chainlock{
        MakeChainLock(865, 864, NonNullHash(864), 43)};
    const FinalChainLockRecordMetadata metadata{
        chainlock.GetLogicalId(genesis), chainlock.GetWitnessId(genesis),
        chainlock.statement};
    BOOST_CHECK(metadata.IsInternallyConsistent(genesis));

    auto malformed{metadata};
    malformed.logical_id = NonNullHash(44);
    BOOST_CHECK(!malformed.IsInternallyConsistent(genesis));
    malformed = metadata;
    malformed.witness_id.SetNull();
    BOOST_CHECK(!malformed.IsInternallyConsistent(genesis));
    malformed = metadata;
    malformed.statement.block_hash.SetNull();
    BOOST_CHECK(!malformed.IsInternallyConsistent(genesis));
    BOOST_CHECK(!metadata.IsInternallyConsistent(uint256{}));
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
