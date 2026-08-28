// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/pq_governance_auth.h>
#include <governance/governance.h>
#include <governance/governancevote.h>
#include <governance/governancevotedb.h>
#include <flatdatabase.h>

#include <chain.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/slhdsa/slhdsa.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <pubkey.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <version.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <memory>
#include <set>
#include <span>
#include <vector>

using namespace llmq::pq;

namespace {

template <std::size_t Size>
void BuildBranch(std::array<CBlockIndex, Size>& indices,
                 std::array<uint256, Size>& hashes,
                 CBlockIndex* parent,
                 int first_height,
                 unsigned char hash_domain,
                 bool build_skip = true)
{
    for (std::size_t i{0}; i < Size; ++i) {
        hashes[i].begin()[0] = hash_domain;
        hashes[i].begin()[1] = static_cast<unsigned char>(i + 1);
        indices[i].nHeight = first_height + static_cast<int>(i);
        indices[i].pprev = i == 0 ? parent : &indices[i - 1];
        indices[i].phashBlock = &hashes[i];
        if (build_skip) indices[i].BuildSkip();
    }
}

slhdsa::SecretKey DeterministicGlobalKey(uint8_t domain)
{
    slhdsa::KeyGenerationSeed seed{};
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(domain + i);
    }
    auto key{slhdsa::GenerateSecretKey(seed)};
    BOOST_REQUIRE(key);
    return std::move(*key);
}

GlobalKeyRecord GlobalKeyFor(const slhdsa::SecretKey& key,
                             uint32_t key_version,
                             uint32_t activated_height)
{
    GlobalKeyRecord record;
    record.key_version = key_version;
    record.activated_height = activated_height;
    BOOST_REQUIRE(key.GetPublicKey(record.public_key));
    record.child_key_commitment.generation = key_version;
    record.child_key_commitment.first_epoch = 7;
    record.child_key_commitment.tree_id.begin()[0] =
        static_cast<uint8_t>(0x80 + key_version);
    record.child_key_commitment.root.begin()[0] =
        static_cast<uint8_t>(0x90 + key_version);
    BOOST_REQUIRE(record.IsStructurallyValid());
    return record;
}

GlobalSignature SignGovernance(const slhdsa::SecretKey& key,
                               GlobalAuthPurpose purpose,
                               const uint256& digest)
{
    GlobalSignature signature;
    BOOST_REQUIRE(slhdsa::SignDeterministic(
        key, std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(purpose), signature));
    return signature;
}

OperatorKeyState CurrentOperatorState(const uint256& pro_tx_hash,
                                      const GlobalKeyRecord& key,
                                      bool active,
                                      uint32_t revoked_height = 0)
{
    auto state{OperatorKeyState::ForOperator(pro_tx_hash)};
    state.has_global_key = 1;
    state.global_key_active = active ? 1 : 0;
    state.revoked_height = revoked_height;
    state.global_key = key;
    state.schedule_initialized = 1;
    state.schedule.last_admissible_epoch = 7;
    BOOST_REQUIRE(state.IsStructurallyValid());
    return state;
}

PQRegistrySnapshot CurrentRegistrySnapshot(
    const CBlockIndex& tip,
    const OperatorKeyState& state,
    std::vector<uint256> used_tree_ids)
{
    PQRegistrySnapshot snapshot;
    snapshot.height = tip.nHeight;
    snapshot.block_hash = tip.GetBlockHash();
    snapshot.previous_block_hash = tip.pprev->GetBlockHash();
    snapshot.operator_states = {state};
    std::sort(used_tree_ids.begin(), used_tree_ids.end());
    snapshot.used_tree_ids = std::move(used_tree_ids);
    const auto root{snapshot.RecomputeConsensusStateRoot(
        Params().GetConsensus().hashGenesisBlock)};
    BOOST_REQUIRE(root);
    snapshot.consensus_state_root = *root;
    BOOST_REQUIRE(snapshot.IsStructurallyValid());
    return snapshot;
}

CDeterministicMNList CurrentMNList(const CBlockIndex& tip,
                                   const uint256& pro_tx_hash,
                                   const COutPoint& collateral)
{
    CDeterministicMNList list{
        tip.GetBlockHash(), tip.nHeight, /*total_registered_count=*/1};
    auto member{std::make_shared<CDeterministicMN>(1)};
    member->proTxHash = pro_tx_hash;
    member->collateralOutpoint = collateral;
    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner.begin()[0] = 1;
    member->pdmnState = std::move(state);
    list.AddMN(member, /*fBumpTotalCount=*/false);
    BOOST_REQUIRE(list.GetValidMNByCollateral(collateral));
    return list;
}

class ScopedPQLegacyAnchor
{
private:
    Consensus::Params& m_consensus;
    const int m_height;
    const uint256 m_block;
    const uint256 m_mn_state;
    const uint256 m_registry_state;

public:
    ScopedPQLegacyAnchor(int height, const uint256& block)
        : m_consensus{
              const_cast<Consensus::Params&>(Params().GetConsensus())},
          m_height{m_consensus.nPQLegacyAnchorHeight},
          m_block{m_consensus.hashPQLegacyAnchorBlock},
          m_mn_state{m_consensus.hashPQLegacyMNState},
          m_registry_state{m_consensus.hashPQLegacyPQRegistryState}
    {
        m_consensus.nPQLegacyAnchorHeight = height;
        m_consensus.hashPQLegacyAnchorBlock = block;
        m_consensus.hashPQLegacyMNState = uint256{1};
        m_consensus.hashPQLegacyPQRegistryState = uint256{2};
    }

    ~ScopedPQLegacyAnchor()
    {
        m_consensus.nPQLegacyAnchorHeight = m_height;
        m_consensus.hashPQLegacyAnchorBlock = m_block;
        m_consensus.hashPQLegacyMNState = m_mn_state;
        m_consensus.hashPQLegacyPQRegistryState = m_registry_state;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(pq_governance_auth_tests)

BOOST_AUTO_TEST_CASE(signing_block_must_be_an_exact_branch_ancestor)
{
    std::array<CBlockIndex, 3> common;
    std::array<uint256, 3> common_hashes;
    BuildBranch(common, common_hashes, nullptr, 0, 0x10);

    std::array<CBlockIndex, 3> main;
    std::array<uint256, 3> main_hashes;
    BuildBranch(main, main_hashes, &common.back(), 3, 0x20);

    std::array<CBlockIndex, 3> fork;
    std::array<uint256, 3> fork_hashes;
    BuildBranch(fork, fork_hashes, &common.back(), 3, 0x30);

    GovernanceAuthorization authorization;
    authorization.signed_height = main[0].nHeight;
    authorization.signed_block_hash = main[0].GetBlockHash();
    authorization.pro_tx_hash.begin()[0] = 1;
    authorization.global_key_version = 1;

    BOOST_CHECK(IsGovernanceAuthorizationOnBranch(main.back(),
                                                   authorization));
    BOOST_CHECK(!IsGovernanceAuthorizationOnBranch(common.back(),
                                                    authorization));
    BOOST_CHECK(!IsGovernanceAuthorizationOnBranch(fork.back(),
                                                    authorization));

    authorization.signed_block_hash = fork[0].GetBlockHash();
    BOOST_CHECK(IsGovernanceAuthorizationOnBranch(fork.back(),
                                                   authorization));
    BOOST_CHECK(!IsGovernanceAuthorizationOnBranch(main.back(),
                                                    authorization));

    authorization.signed_height = -1;
    BOOST_CHECK(!IsGovernanceAuthorizationOnBranch(fork.back(),
                                                    authorization));
}

BOOST_AUTO_TEST_CASE(unavailable_dmn_context_fails_closed_without_height_access)
{
    uint256 branch_hash;
    branch_hash.begin()[0] = 1;
    CBlockIndex branch;
    branch.nHeight = 0;
    branch.phashBlock = &branch_hash;

    GovernanceAuthorization source;
    source.signed_height = branch.nHeight;
    source.signed_block_hash = branch_hash;
    source.pro_tx_hash.begin()[0] = 2;
    source.global_key_version = 1;
    source.signature[0] = 1;
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(source, encoded));

    GovernanceAuthorization decoded;
    std::string error;
    BOOST_CHECK(!CheckGovernanceAuthorizationContext(
        branch, CDeterministicMNList{}, PQRegistrySnapshot{}, COutPoint{},
        encoded, decoded, error));
    BOOST_CHECK_EQUAL(error, "governance validation contexts do not match");
}

BOOST_FIXTURE_TEST_CASE(
    current_key_authorizes_older_height_until_rotation_or_revocation,
    BasicTestingSetup)
{
    const int anchor_height{Params().GetConsensus().DIP0003Height};
    std::array<CBlockIndex, 4> branch;
    std::array<uint256, 4> hashes;
    BuildBranch(branch, hashes, nullptr, anchor_height, 0x40,
                /*build_skip=*/false);
    ScopedPQLegacyAnchor anchor{anchor_height, hashes.front()};

    const uint256 pro_tx_hash{uint256{10}};
    const COutPoint collateral{uint256{11}, 1};
    const uint256 payload_hash{uint256{12}};
    const auto mn_list{
        CurrentMNList(branch.back(), pro_tx_hash, collateral)};

    auto signing_secret{DeterministicGlobalKey(0x20)};
    const auto signing_key{GlobalKeyFor(
        signing_secret, /*key_version=*/1,
        static_cast<uint32_t>(anchor_height))};
    GovernanceAuthorization authorization;
    authorization.signed_height = branch[1].nHeight;
    authorization.signed_block_hash = branch[1].GetBlockHash();
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = signing_key.key_version;
    const auto digest{GetGovernanceAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, signing_key,
        authorization, GovernanceAuthPurpose::TRIGGER, payload_hash)};
    BOOST_REQUIRE(digest);
    authorization.signature = SignGovernance(
        signing_secret, GlobalAuthPurpose::GOVERNANCE_TRIGGER, *digest);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(authorization, encoded));

    const auto current_state{
        CurrentOperatorState(pro_tx_hash, signing_key, /*active=*/true)};
    const auto current_snapshot{CurrentRegistrySnapshot(
        branch.back(), current_state,
        {signing_key.child_key_commitment.tree_id})};
    std::string error;
    BOOST_CHECK(VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, current_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK(error.empty());

    auto replacement_secret{DeterministicGlobalKey(0x60)};
    const auto replacement_key{GlobalKeyFor(
        replacement_secret, /*key_version=*/2,
        static_cast<uint32_t>(branch[2].nHeight))};
    const auto rotated_snapshot{CurrentRegistrySnapshot(
        branch.back(),
        CurrentOperatorState(pro_tx_hash, replacement_key, /*active=*/true),
        {signing_key.child_key_commitment.tree_id,
         replacement_key.child_key_commitment.tree_id})};
    BOOST_CHECK(!VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, rotated_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK_EQUAL(
        error, "governance signer key is revoked, rotated, or replaced");

    const auto revoked_snapshot{CurrentRegistrySnapshot(
        branch.back(),
        CurrentOperatorState(
            pro_tx_hash, signing_key, /*active=*/false,
            static_cast<uint32_t>(branch[2].nHeight)),
        {signing_key.child_key_commitment.tree_id})};
    BOOST_CHECK(!VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, revoked_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK_EQUAL(
        error, "governance signer key is revoked, rotated, or replaced");

    auto wrong_version{authorization};
    ++wrong_version.global_key_version;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(wrong_version, encoded));
    BOOST_CHECK(!VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, current_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK_EQUAL(
        error, "governance signer key is revoked, rotated, or replaced");
}

BOOST_AUTO_TEST_CASE(governance_signature_vector_is_bounded_before_relay)
{
    uint256 parent_hash;
    parent_hash.begin()[0] = 1;
    COutPoint outpoint{parent_hash, 0};
    CGovernanceVote vote{outpoint, parent_hash, VOTE_SIGNAL_FUNDING,
                         VOTE_OUTCOME_YES};
    const uint256 unsigned_hash{vote.GetSignatureHash()};
    vote.SetSignature(std::vector<unsigned char>(
        MAX_GOVERNANCE_SIGNATURE_SIZE + 1, 0x01));
    BOOST_CHECK(vote.GetSignatureHash() == unsigned_hash);
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK_THROW(stream << vote, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(governance_vote_ordering_is_strict_and_cache_safe)
{
    const uint256 parent{uint256{60}};
    const COutPoint first_outpoint{uint256{61}, 0};
    const COutPoint second_outpoint{uint256{62}, 0};
    CGovernanceVote first{first_outpoint, parent, VOTE_SIGNAL_FUNDING,
                          VOTE_OUTCOME_YES};
    CGovernanceVote second{second_outpoint, parent, VOTE_SIGNAL_FUNDING,
                           VOTE_OUTCOME_YES};
    first.SetTime(100);
    second.SetTime(100);

    const auto is_strictly_ordered{
        [](const CGovernanceVote& lhs, const CGovernanceVote& rhs) {
            return (lhs < rhs) != (rhs < lhs);
        }};
    BOOST_CHECK(is_strictly_ordered(first, second));

    CGovernanceVote parent_variant{
        first_outpoint, uint256{63}, VOTE_SIGNAL_FUNDING,
        VOTE_OUTCOME_YES};
    parent_variant.SetTime(100);
    BOOST_CHECK(is_strictly_ordered(first, parent_variant));
    CGovernanceVote outcome_variant{
        first_outpoint, parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_NO};
    outcome_variant.SetTime(100);
    BOOST_CHECK(is_strictly_ordered(first, outcome_variant));
    CGovernanceVote signal_variant{
        first_outpoint, parent, VOTE_SIGNAL_VALID, VOTE_OUTCOME_YES};
    signal_variant.SetTime(100);
    BOOST_CHECK(is_strictly_ordered(first, signal_variant));
    CGovernanceVote time_variant{first};
    time_variant.SetTime(101);
    BOOST_CHECK(is_strictly_ordered(first, time_variant));

    // SYSCOIN: distinct same-parent votes must coexist in the orphan cache,
    // while changing only a signature/expiry must not mint another vote.
    CacheMultiMap<uint256, vote_time_pair_t> cache{4};
    BOOST_REQUIRE(cache.Insert(parent, vote_time_pair_t{first, 1'000}));
    BOOST_REQUIRE(cache.Insert(parent, vote_time_pair_t{second, 1'001}));
    CGovernanceVote duplicate{first};
    duplicate.SetSignature({0x01});
    BOOST_CHECK(first == duplicate);
    BOOST_CHECK(!(first < duplicate));
    BOOST_CHECK(!(duplicate < first));
    BOOST_CHECK(!cache.Insert(parent,
                              vote_time_pair_t{duplicate, 2'000}));
    BOOST_CHECK_EQUAL(cache.GetSize(), 2U);
}

BOOST_AUTO_TEST_CASE(governance_vote_authority_is_object_and_signal_specific)
{
    BOOST_CHECK(!GetGovernanceVoteAuthPurpose(
        GOVERNANCE_OBJECT_PROPOSAL, VOTE_SIGNAL_FUNDING));
    for (const auto signal : {VOTE_SIGNAL_VALID, VOTE_SIGNAL_DELETE,
                              VOTE_SIGNAL_ENDORSED}) {
        const auto purpose{GetGovernanceVoteAuthPurpose(
            GOVERNANCE_OBJECT_PROPOSAL, signal)};
        BOOST_REQUIRE(purpose);
        BOOST_CHECK(*purpose == GovernanceAuthPurpose::PROPOSAL_VOTE);
    }
    for (const auto signal : {VOTE_SIGNAL_FUNDING, VOTE_SIGNAL_VALID,
                              VOTE_SIGNAL_DELETE,
                              VOTE_SIGNAL_ENDORSED}) {
        const auto purpose{GetGovernanceVoteAuthPurpose(
            GOVERNANCE_OBJECT_TRIGGER, signal)};
        BOOST_REQUIRE(purpose);
        BOOST_CHECK(*purpose == GovernanceAuthPurpose::TRIGGER_VOTE);
    }
    BOOST_CHECK(!GetGovernanceVoteAuthPurpose(
        GOVERNANCE_OBJECT_PROPOSAL, VOTE_SIGNAL_NONE));
    BOOST_CHECK(!GetGovernanceVoteAuthPurpose(
        GOVERNANCE_OBJECT_UNKNOWN, VOTE_SIGNAL_DELETE));
}

BOOST_AUTO_TEST_CASE(orphan_vote_encoding_is_signal_specific)
{
    constexpr std::size_t compact{CPubKey::COMPACT_SIGNATURE_SIZE};
    constexpr std::size_t slh{GovernanceAuthorization::WIRE_SIZE};

    BOOST_CHECK(IsPotentialOrphanGovernanceVoteAuthorization(
        VOTE_SIGNAL_FUNDING, compact));
    BOOST_CHECK(IsPotentialOrphanGovernanceVoteAuthorization(
        VOTE_SIGNAL_FUNDING, slh));
    for (const auto signal : {VOTE_SIGNAL_VALID, VOTE_SIGNAL_DELETE,
                              VOTE_SIGNAL_ENDORSED}) {
        BOOST_CHECK(!IsPotentialOrphanGovernanceVoteAuthorization(
            signal, compact));
        BOOST_CHECK(IsPotentialOrphanGovernanceVoteAuthorization(
            signal, slh));
    }
    BOOST_CHECK(!IsPotentialOrphanGovernanceVoteAuthorization(
        VOTE_SIGNAL_NONE, compact));
    BOOST_CHECK(!IsPotentialOrphanGovernanceVoteAuthorization(
        VOTE_SIGNAL_FUNDING, compact + 1));
}

BOOST_AUTO_TEST_CASE(operator_vote_sync_verification_is_globally_and_source_bounded)
{
    BOOST_CHECK_LE(
        GovernanceVoteSyncRateLimiter::MAX_VERIFICATIONS_PER_REQUEST,
        256U);
    GovernanceVoteSyncRateLimiter limiter;
    const auto now{std::chrono::microseconds{100}};
    const uint64_t keyed_group{0x1234};

    BOOST_CHECK(limiter.Consume(/*peer=*/1, {}, keyed_group, now));
    BOOST_CHECK(!limiter.Consume(
        /*peer=*/2, {}, keyed_group + 1,
        now + GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL -
            std::chrono::microseconds{1}));
    BOOST_CHECK(limiter.Consume(
        /*peer=*/2, {}, keyed_group + 1,
        now + GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));

    const auto second_window{
        now + 2 * GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL};
    BOOST_CHECK(limiter.Consume(
        /*peer=*/3, {}, keyed_group, second_window));
    BOOST_CHECK(!limiter.Consume(
        /*peer=*/4, {}, keyed_group,
        second_window +
            GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));
    BOOST_CHECK(limiter.Consume(
        /*peer=*/4, {}, keyed_group,
        second_window +
            GovernanceVoteSyncRateLimiter::SOURCE_REFILL_INTERVAL));

    GovernanceVoteSyncRateLimiter authenticated;
    const uint256 pro_tx_hash{uint256S("a001")};
    BOOST_CHECK(authenticated.Consume(
        /*peer=*/10, pro_tx_hash, 1, now));
    BOOST_CHECK(authenticated.Consume(
        /*peer=*/11, pro_tx_hash, 2,
        now + GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));
    BOOST_CHECK(!authenticated.Consume(
        /*peer=*/12, pro_tx_hash, 3,
        now + 2 * GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));
    BOOST_CHECK(authenticated.Consume(
        /*peer=*/12, {}, keyed_group,
        now + 2 * GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));
    BOOST_CHECK_EQUAL(authenticated.Size(), 2U);

    GovernanceVoteSyncRateLimiter cooldown;
    BOOST_REQUIRE(cooldown.Consume(/*peer=*/20, {}, /*keyed_net_group=*/0,
                                   now));
    for (int64_t peer{21}; peer < 64; ++peer) {
        BOOST_CHECK(!cooldown.Consume(
            peer, {}, /*keyed_net_group=*/0,
            now + std::chrono::microseconds{1}));
    }
    BOOST_CHECK_EQUAL(cooldown.Size(), 1U);

    GovernanceVoteSyncRateLimiter bounded;
    for (std::size_t source{0};
         source < GovernanceVoteSyncRateLimiter::MAX_SOURCES + 32;
         ++source) {
        BOOST_REQUIRE(bounded.Consume(
            static_cast<int64_t>(source), {}, /*keyed_net_group=*/0,
            now + source *
                GovernanceVoteSyncRateLimiter::GLOBAL_MIN_INTERVAL));
    }
    BOOST_CHECK_EQUAL(
        bounded.Size(), GovernanceVoteSyncRateLimiter::MAX_SOURCES);
}

BOOST_AUTO_TEST_CASE(authority_delta_vote_lookup_is_operator_bounded)
{
    constexpr std::size_t operator_count{256};
    CGovernanceObjectVoteFile votes;
    const uint256 parent_hash{uint256{70}};
    std::array<COutPoint, operator_count> outpoints;
    for (std::size_t index{0}; index < operator_count; ++index) {
        uint256 collateral_hash;
        WriteLE64(collateral_hash.begin(), index + 1);
        outpoints[index] = COutPoint{
            collateral_hash, static_cast<uint32_t>(index)};
        CGovernanceVote vote{
            outpoints[index], parent_hash, VOTE_SIGNAL_VALID,
            VOTE_OUTCOME_YES};
        vote.SetTime(static_cast<int64_t>(index + 1));
        votes.AddVote(vote);
    }
    BOOST_REQUIRE_EQUAL(votes.GetVoteCount(), operator_count);

    constexpr std::size_t selected{173};
    std::size_t selected_callbacks{0};
    votes.ForEachVoteFromMasternode(
        outpoints[selected], [&](const CGovernanceVote& vote) {
            ++selected_callbacks;
            BOOST_CHECK(vote.GetMasternodeOutpoint() ==
                        outpoints[selected]);
            return true;
        });
    BOOST_CHECK_EQUAL(selected_callbacks, 1U);

    // An empty roster invalidates only the selected operator's indexed vote;
    // unrelated operators are neither visited nor removed.
    const CDeterministicMNList empty_list{
        uint256{71}, /*height=*/1, /*total_registered_count=*/0};
    const auto removed{votes.RemoveInvalidVotes(
        empty_list, outpoints[selected], /*fProposal=*/false)};
    BOOST_CHECK_EQUAL(removed.size(), 1U);
    BOOST_CHECK_EQUAL(votes.GetVoteCount(), operator_count - 1);
    BOOST_CHECK(!votes.HasVoteFromMasternode(outpoints[selected]));
    BOOST_CHECK(votes.HasVoteFromMasternode(outpoints[selected - 1]));
    BOOST_CHECK(votes.HasVoteFromMasternode(outpoints[selected + 1]));
}

BOOST_AUTO_TEST_CASE(governance_vote_pages_follow_exact_hash_index_order)
{
    CGovernanceObjectVoteFile votes;
    const uint256 parent{uint256{75}};
    std::set<uint256> expected;
    for (std::size_t i{0}; i < 5; ++i) {
        CGovernanceVote vote{
            COutPoint{uint256{static_cast<uint8_t>(100 + i)},
                      static_cast<uint32_t>(i)},
            parent, VOTE_SIGNAL_VALID, VOTE_OUTCOME_YES};
        vote.SetTime(static_cast<int64_t>(100 - i));
        vote.SetSignature(std::vector<unsigned char>{
            static_cast<unsigned char>(i + 1)});
        expected.insert(vote.GetHash());
        votes.AddVote(vote);
    }

    const auto budget{
        std::make_shared<GovernancePageSnapshotBudget>()};
    const auto snapshot{votes.GetPageSnapshot(
        parent, budget, /*instance_id=*/1,
        /*validation_context_epoch=*/1)};
    BOOST_REQUIRE(snapshot);
    BOOST_CHECK_EQUAL(snapshot->TotalCount(), expected.size());
    std::vector<uint256> received;
    for (const auto& entry : snapshot->Entries()) {
        BOOST_CHECK_EQUAL(
            entry.inv.type, MSG_GOVERNANCE_OBJECT_VOTE);
        received.push_back(entry.inv.hash);
        CDataStream stream{
            Span<const uint8_t>{entry.payload}, SER_NETWORK,
            GOVERNANCE_PAGE_PROTO_VERSION};
        CGovernanceVote decoded;
        stream >> decoded;
        BOOST_CHECK(decoded.GetHash() == entry.inv.hash);
        BOOST_CHECK(stream.empty());
    }
    BOOST_REQUIRE_EQUAL(received.size(), expected.size());
    BOOST_CHECK(std::equal(
        received.begin(), received.end(), expected.begin()));

    CGovernanceVote later{
        COutPoint{uint256{200}, 9}, parent,
        VOTE_SIGNAL_VALID, VOTE_OUTCOME_NO};
    later.SetTime(999);
    later.SetSignature(std::vector<unsigned char>{0x42});
    votes.AddVote(later);
    const auto changed{votes.GetPageSnapshot(
        parent, budget, /*instance_id=*/2,
        /*validation_context_epoch=*/1)};
    BOOST_REQUIRE(changed);
    BOOST_CHECK(changed != snapshot);
    BOOST_CHECK(changed->ViewId() != snapshot->ViewId());
    BOOST_CHECK_EQUAL(changed->TotalCount(), expected.size() + 1);
    BOOST_CHECK_EQUAL(snapshot->TotalCount(), expected.size());

    const auto new_context{votes.GetPageSnapshot(
        parent, budget, /*instance_id=*/3,
        /*validation_context_epoch=*/2)};
    BOOST_REQUIRE(new_context);
    BOOST_CHECK(new_context != changed);
    BOOST_CHECK(new_context->ViewId() == changed->ViewId());
    BOOST_CHECK_EQUAL(new_context->ValidationContextEpoch(), 2U);
}

BOOST_AUTO_TEST_CASE(governance_vote_bytes_and_flatdb_sizes_are_checked)
{
    CGovernanceObjectVoteFile votes;
    const uint256 parent{uint256{80}};
    const COutPoint outpoint{uint256{81}, 0};

    CGovernanceVote first{
        outpoint, parent, VOTE_SIGNAL_VALID, VOTE_OUTCOME_YES};
    first.SetTime(1);
    first.SetSignature(std::vector<unsigned char>{0x01});
    votes.AddVote(first);
    const uint64_t first_bytes{votes.GetSerializedVoteBytes()};
    BOOST_REQUIRE_GT(first_bytes, 0U);

    CGovernanceVote replacement{
        outpoint, parent, VOTE_SIGNAL_VALID, VOTE_OUTCOME_NO};
    replacement.SetTime(2);
    replacement.SetSignature(std::vector<unsigned char>(257, 0x02));
    const uint64_t projected{
        votes.ProjectedSerializedVoteBytes(replacement)};
    BOOST_CHECK_GT(projected, first_bytes);
    votes.AddVote(replacement);
    BOOST_CHECK_EQUAL(votes.GetSerializedVoteBytes(), projected);
    BOOST_CHECK_EQUAL(votes.GetVoteCount(), 1);

    const auto precharge{
        votes.GetVoteSerializedSizeUpperBound(
            replacement.GetHash(), PROTOCOL_VERSION)};
    BOOST_REQUIRE(precharge);
    CGovernanceVote alternate{replacement};
    alternate.SetSignature(std::vector<unsigned char>(
        MAX_GOVERNANCE_SIGNATURE_SIZE, 0x03));
    BOOST_CHECK(alternate.GetHash() == replacement.GetHash());
    BOOST_CHECK_GE(
        *precharge,
        ::GetSerializeSize(alternate, PROTOCOL_VERSION, SER_NETWORK));

    constexpr uint64_t limit{768ULL << 20};
    BOOST_CHECK(!FlatDatabaseFileSizeAllowed(sizeof(uint256) - 1, limit));
    BOOST_CHECK(FlatDatabaseFileSizeAllowed(sizeof(uint256), limit));
    BOOST_CHECK(FlatDatabaseFileSizeAllowed(limit, limit));
    BOOST_CHECK(!FlatDatabaseFileSizeAllowed(
        static_cast<uintmax_t>(limit) + 1, limit));
    const uintmax_t beyond_int{
        static_cast<uintmax_t>(std::numeric_limits<int>::max()) + 1};
    BOOST_CHECK(!FlatDatabaseFileSizeAllowed(beyond_int, limit));
    BOOST_CHECK(FlatDatabaseFileSizeAllowed(
        beyond_int, std::numeric_limits<uint64_t>::max()));
}

BOOST_AUTO_TEST_SUITE_END()
