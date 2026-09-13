// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <governance/pq_governance_auth.h>
#include <governance/governance.h>
#include <governance/governanceobject.h>
#include <governance/governancevote.h>
#include <governance/governancevotedb.h>
#include <flatdatabase.h>

#include <chain.h>
#include <chainparams.h>
#include <crypto/common.h>
#include <crypto/slhdsa/slhdsa.h>
#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <evo/pq_voting_key.h>
#include <key.h>
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
                             const uint256& pro_tx_hash,
                             uint32_t key_version,
                             uint32_t activated_height)
{
    GlobalKeyRecord record;
    record.key_version = key_version;
    record.activated_height = activated_height;
    BOOST_REQUIRE(key.GetPublicKey(record.public_key));
    record.child_key_commitment.generation = key_version;
    record.child_key_commitment.first_epoch = 7;
    const auto tree_id{GetChildKeyTreeId(
        Params().GetConsensus().hashGenesisBlock, pro_tx_hash,
        record.child_key_commitment.generation,
        record.child_key_commitment.first_epoch)};
    BOOST_REQUIRE(tree_id);
    record.child_key_commitment.tree_id = *tree_id;
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
    const OperatorKeyState& state)
{
    PQRegistrySnapshot snapshot;
    snapshot.height = tip.nHeight;
    snapshot.block_hash = tip.GetBlockHash();
    snapshot.previous_block_hash = tip.pprev->GetBlockHash();
    snapshot.operator_states = {state};
    const auto root{snapshot.RecomputeConsensusStateRoot(
        Params().GetConsensus().hashGenesisBlock)};
    BOOST_REQUIRE(root);
    snapshot.consensus_state_root = *root;
    BOOST_REQUIRE(snapshot.IsStructurallyValid());
    return snapshot;
}

CDeterministicMNList CurrentMNList(const CBlockIndex& tip,
                                   const uint256& pro_tx_hash,
                                   const COutPoint& collateral,
                                   const VotingKeyRecord& voting_key = {},
                                   const CKeyID& legacy_voting_key = {})
{
    CDeterministicMNList list{
        tip.GetBlockHash(), tip.nHeight, /*total_registered_count=*/1};
    auto member{std::make_shared<CDeterministicMN>(1)};
    member->proTxHash = pro_tx_hash;
    member->collateralOutpoint = collateral;
    auto state{std::make_shared<CDeterministicMNState>()};
    state->keyIDOwner.begin()[0] = 1;
    state->pqVotingKey = voting_key;
    state->keyIDVoting = legacy_voting_key;
    member->pdmnState = std::move(state);
    list.AddMN(member, /*fBumpTotalCount=*/false);
    BOOST_REQUIRE(list.GetValidMNByCollateral(collateral));
    return list;
}

class ScopedPQActivation
{
private:
    Consensus::Params& m_consensus;
    const int m_height;

public:
    explicit ScopedPQActivation(int height)
        : m_consensus{
              const_cast<Consensus::Params&>(Params().GetConsensus())},
          m_height{m_consensus.nPQActivationHeight}
    {
        m_consensus.nPQActivationHeight = height;
    }

    ~ScopedPQActivation()
    {
        m_consensus.nPQActivationHeight = m_height;
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
        encoded, decoded, error, GovernanceAuthPurpose::TRIGGER));
    BOOST_CHECK_EQUAL(error, "governance validation contexts do not match");
}

BOOST_FIXTURE_TEST_CASE(
    current_key_authorizes_activation_block_until_rotation_or_revocation,
    BasicTestingSetup)
{
    const int activation_height{Params().GetConsensus().DIP0003Height};
    BOOST_REQUIRE_GT(activation_height, 0);
    std::array<CBlockIndex, 4> branch;
    std::array<uint256, 4> hashes;
    BuildBranch(branch, hashes, nullptr, activation_height - 1, 0x40,
                /*build_skip=*/false);
    ScopedPQActivation activation{activation_height};

    const uint256 pro_tx_hash{uint256{10}};
    const COutPoint collateral{uint256{11}, 1};
    const uint256 payload_hash{uint256{12}};
    const auto mn_list{
        CurrentMNList(branch.back(), pro_tx_hash, collateral)};

    auto signing_secret{DeterministicGlobalKey(0x20)};
    const auto signing_key{GlobalKeyFor(
        signing_secret, pro_tx_hash, /*key_version=*/1,
        static_cast<uint32_t>(activation_height - 1))};
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
        branch.back(), current_state)};
    std::string error;
    BOOST_CHECK(VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, current_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK(error.empty());

    auto pre_activation{authorization};
    pre_activation.signed_height = branch.front().nHeight;
    pre_activation.signed_block_hash = branch.front().GetBlockHash();
    const auto pre_activation_digest{GetGovernanceAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, signing_key,
        pre_activation, GovernanceAuthPurpose::TRIGGER, payload_hash)};
    BOOST_REQUIRE(pre_activation_digest);
    pre_activation.signature = SignGovernance(
        signing_secret, GlobalAuthPurpose::GOVERNANCE_TRIGGER,
        *pre_activation_digest);
    std::vector<unsigned char> pre_activation_encoded;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(
        pre_activation, pre_activation_encoded));
    BOOST_CHECK(!VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, current_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash,
        pre_activation_encoded, error));
    BOOST_CHECK_EQUAL(error,
                      "governance authorization predates PQ activation");

    auto replacement_secret{DeterministicGlobalKey(0x60)};
    const auto replacement_key{GlobalKeyFor(
        replacement_secret, pro_tx_hash, /*key_version=*/2,
        static_cast<uint32_t>(branch[2].nHeight))};
    const auto rotated_snapshot{CurrentRegistrySnapshot(
        branch.back(),
        CurrentOperatorState(pro_tx_hash, replacement_key, /*active=*/true))};
    BOOST_CHECK(!VerifyGovernanceAuthorizationForBranch(
        branch.back(), mn_list, rotated_snapshot, collateral,
        GovernanceAuthPurpose::TRIGGER, payload_hash, encoded, error));
    BOOST_CHECK_EQUAL(
        error, "governance signer key is revoked, rotated, or replaced");

    const auto revoked_snapshot{CurrentRegistrySnapshot(
        branch.back(),
        CurrentOperatorState(
            pro_tx_hash, signing_key, /*active=*/false,
            static_cast<uint32_t>(branch[2].nHeight)))};
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

BOOST_FIXTURE_TEST_CASE(
    funding_voting_key_is_independent_of_operator_and_bound_to_branch_and_payload,
    BasicTestingSetup)
{
    const int height{Params().GetConsensus().DIP0003Height};
    ScopedPQActivation activation{height};
    std::array<CBlockIndex, 4> branch;
    std::array<uint256, 4> hashes;
    BuildBranch(branch, hashes, nullptr, height - 1, 0x91, false);
    std::array<CBlockIndex, 2> fork;
    std::array<uint256, 2> fork_hashes;
    BuildBranch(fork, fork_hashes, &branch[0], height, 0x92, false);

    const uint256 pro_tx_hash{uint256{91}};
    const COutPoint collateral{uint256{92}, 0};
    auto operator_secret{DeterministicGlobalKey(0x93)};
    const auto operator_key{GlobalKeyFor(operator_secret, pro_tx_hash, 1, height)};
    const auto snapshot{CurrentRegistrySnapshot(
        branch.back(), CurrentOperatorState(pro_tx_hash, operator_key, true))};
    auto voting_secret{DeterministicGlobalKey(0x94)};
    VotingKeyRecord voting_key;
    BOOST_REQUIRE(voting_secret.GetPublicKey(voting_key.public_key));
    voting_key.key_version = 1;
    voting_key.activated_height = height;
    const auto list{CurrentMNList(branch.back(), pro_tx_hash, collateral, voting_key)};
    CGovernanceVote vote{collateral, uint256{93}, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    vote.SetTime(100);
    GovernanceAuthorization authorization;
    authorization.signed_height = height;
    authorization.signed_block_hash = branch[1].GetBlockHash();
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = voting_key.key_version;
    const auto& genesis{Params().GetConsensus().hashGenesisBlock};
    const auto digest{GetGovernanceFundingAuthorizationHash(
        genesis, voting_key, authorization, vote.GetSignatureHash())};
    BOOST_REQUIRE(digest);
    authorization.signature = SignGovernance(
        voting_secret, GlobalAuthPurpose::GOVERNANCE_PROPOSAL_FUNDING_VOTE, *digest);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(EncodeGovernanceAuthorization(authorization, encoded));
    vote.SetSignature(encoded);
    const auto verify = [&](const CBlockIndex& tip,
                            const CDeterministicMNList& current_list,
                            const PQRegistrySnapshot& current_snapshot,
                            GovernanceAuthPurpose purpose = GovernanceAuthPurpose::PROPOSAL_FUNDING_VOTE) {
        std::string error;
        return VerifyGovernanceAuthorizationForBranch(
            tip, current_list, current_snapshot, collateral, purpose,
            vote.GetSignatureHash(), encoded, error);
    };
    BOOST_REQUIRE(verify(branch.back(), list, snapshot));
    BOOST_CHECK(!verify(branch.back(), list, snapshot, GovernanceAuthPurpose::TRIGGER_VOTE));
    BOOST_CHECK(!verify(branch.back(), list, snapshot, GovernanceAuthPurpose::PROPOSAL_VOTE));
    BOOST_CHECK(!GetGovernanceAuthorizationHash(
        genesis, operator_key, authorization, GovernanceAuthPurpose::PROPOSAL_FUNDING_VOTE,
        vote.GetSignatureHash()));

    // A live funding delegation survives both operator rotation and revocation.
    auto rotated_operator_key{operator_key};
    ++rotated_operator_key.key_version;
    BOOST_CHECK(verify(branch.back(), list, CurrentRegistrySnapshot(
        branch.back(), CurrentOperatorState(pro_tx_hash, rotated_operator_key, true))));
    BOOST_CHECK(verify(branch.back(), list, CurrentRegistrySnapshot(
        branch.back(), CurrentOperatorState(pro_tx_hash, operator_key, false, height + 1))));
    const auto fork_list{CurrentMNList(fork.back(), pro_tx_hash, collateral, voting_key)};
    const auto fork_snapshot{CurrentRegistrySnapshot(
        fork.back(), CurrentOperatorState(pro_tx_hash, operator_key, true))};
    BOOST_CHECK(!verify(fork.back(), fork_list, fork_snapshot));

    BOOST_CHECK(!VerifyGovernanceFundingAuthorization(
        uint256{94}, voting_key, authorization, vote.GetSignatureHash()));
    BOOST_CHECK(!VerifyGovernanceFundingAuthorization(
        genesis, voting_key, authorization, uint256{95}));
    CGovernanceVote changed_signal{collateral, vote.GetParentHash(), VOTE_SIGNAL_VALID, VOTE_OUTCOME_YES};
    changed_signal.SetTime(vote.GetTimestamp());
    BOOST_CHECK(!VerifyGovernanceFundingAuthorization(
        genesis, voting_key, authorization, changed_signal.GetSignatureHash()));

    auto rotated_voting_key{voting_key};
    ++rotated_voting_key.key_version;
    rotated_voting_key.activated_height = height + 1;
    BOOST_CHECK(!verify(branch.back(), CurrentMNList(
        branch.back(), pro_tx_hash, collateral, rotated_voting_key), snapshot));
    auto revoked_voting_key{rotated_voting_key};
    revoked_voting_key.public_key = {};
    BOOST_CHECK(!verify(branch.back(), CurrentMNList(
        branch.back(), pro_tx_hash, collateral, revoked_voting_key), snapshot));
    BOOST_CHECK(!verify(branch.back(), CurrentMNList(
        branch.back(), pro_tx_hash, collateral), snapshot));
    BOOST_CHECK(!verify(branch.back(), CurrentMNList(
        branch.back(), uint256{96}, collateral, voting_key), snapshot));
    auto premature_key{voting_key};
    premature_key.activated_height = height + 1;
    BOOST_CHECK(!GovernanceAuthorizationMatchesCurrentVotingKey(authorization, premature_key));

    // Even a genuine operator signature in the funding domain is not a delegation.
    auto wrong_signer{authorization};
    wrong_signer.signature = SignGovernance(
        operator_secret, GlobalAuthPurpose::GOVERNANCE_PROPOSAL_FUNDING_VOTE, *digest);
    BOOST_REQUIRE(EncodeGovernanceAuthorization(wrong_signer, encoded));
    BOOST_CHECK(!verify(branch.back(), list, snapshot));
    auto wrong_domain{authorization};
    wrong_domain.signature = SignGovernance(
        voting_secret, GlobalAuthPurpose::GOVERNANCE_PROPOSAL_VOTE, *digest);
    BOOST_REQUIRE(EncodeGovernanceAuthorization(wrong_domain, encoded));
    BOOST_CHECK(!verify(branch.back(), list, snapshot));
}

BOOST_FIXTURE_TEST_CASE(legacy_funding_deactivates_at_activation_and_recovers_on_rollback,
                        BasicTestingSetup)
{
    const int height{Params().GetConsensus().DIP0003Height};
    ScopedPQActivation activation{height};
    std::array<CBlockIndex, 3> branch;
    std::array<uint256, 3> hashes;
    BuildBranch(branch, hashes, nullptr, height - 2, 0xa1, false);
    const uint256 pro_tx_hash{uint256{101}};
    const COutPoint collateral{uint256{102}, 0};
    CKey legacy_key;
    legacy_key.MakeNewKey(true);
    const auto legacy_id{legacy_key.GetPubKey().GetID()};
    auto operator_secret{DeterministicGlobalKey(0xa2)};
    const auto operator_key{GlobalKeyFor(operator_secret, pro_tx_hash, 1, height - 1)};
    const auto operator_state{CurrentOperatorState(pro_tx_hash, operator_key, true)};
    CGovernanceObject proposal{uint256{}, 1, 100, uint256{}, "7b2274797065223a317d"};
    CGovernanceVote vote{collateral, proposal.GetHash(), VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    vote.SetTime(100);
    BOOST_REQUIRE(vote.Sign(legacy_key, legacy_id));
    auto& stored{const_cast<CGovernanceObjectVoteFile&>(proposal.GetVoteFile())};
    stored.AddVote(vote, true);
    const auto reconcile = [&](CGovernanceObject& object, const CBlockIndex& tip) {
        const auto list{CurrentMNList(tip, pro_tx_hash, collateral, {}, legacy_id)};
        const auto snapshot{CurrentRegistrySnapshot(tip, operator_state)};
        object.RemoveInvalidPQVotes(tip, list, snapshot);
    };
    const auto before{CurrentMNList(branch[1], pro_tx_hash, collateral, {}, legacy_id)};
    const auto after{CurrentMNList(branch[2], pro_tx_hash, collateral, {}, legacy_id)};
    BOOST_REQUIRE(vote.IsValid(before));
    BOOST_CHECK(!vote.IsValid(after));
    BOOST_CHECK(!GetGovernanceVoteAuthPurpose(GOVERNANCE_OBJECT_PROPOSAL, VOTE_SIGNAL_FUNDING, height - 1));
    BOOST_CHECK(GetGovernanceVoteAuthPurpose(GOVERNANCE_OBJECT_PROPOSAL, VOTE_SIGNAL_FUNDING, height));
    BOOST_CHECK(IsPotentialOrphanGovernanceVoteAuthorization(VOTE_SIGNAL_FUNDING, vote.GetSignatureSize(), height - 1));
    BOOST_CHECK(!IsPotentialOrphanGovernanceVoteAuthorization(VOTE_SIGNAL_FUNDING, vote.GetSignatureSize(), height));
    reconcile(proposal, branch[1]);
    BOOST_CHECK_EQUAL(proposal.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 1);
    const auto bytes{stored.GetSerializedVoteBytes()};
    reconcile(proposal, branch[2]);
    BOOST_CHECK_EQUAL(proposal.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 0);
    BOOST_CHECK_EQUAL(stored.GetSerializedVoteBytes(), bytes);
    CDataStream disk{SER_DISK, PROTOCOL_VERSION};
    disk << proposal;
    CGovernanceObject reloaded;
    disk >> reloaded;
    reconcile(reloaded, branch[1]);
    BOOST_CHECK_EQUAL(reloaded.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 1);
    BOOST_REQUIRE(reloaded.GetVoteFile().GetVote(vote.GetHash()));
    BOOST_CHECK(reloaded.GetVoteFile().GetVote(vote.GetHash())->HasSameWireEncoding(vote));
    reconcile(reloaded, branch[2]);
    BOOST_CHECK_EQUAL(reloaded.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 0);
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
    const auto funding{GetGovernanceVoteAuthPurpose(
        GOVERNANCE_OBJECT_PROPOSAL, VOTE_SIGNAL_FUNDING)};
    BOOST_REQUIRE(funding);
    BOOST_CHECK(*funding == GovernanceAuthPurpose::PROPOSAL_FUNDING_VOTE);
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

    BOOST_CHECK(!IsPotentialOrphanGovernanceVoteAuthorization(
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

// SYSCOIN: Vote invalidation checks activation against initialized chain parameters.
BOOST_FIXTURE_TEST_CASE(authority_delta_vote_lookup_is_operator_bounded, BasicTestingSetup)
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

BOOST_AUTO_TEST_CASE(governance_snapshot_spool_is_immutable_and_releases_budget)
{
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>()};
    constexpr std::size_t block_size{1ULL << 20};
    constexpr uint32_t block_count{65};
    {
        auto spool{GovernancePagePayloadSpool::Create(
            budget, block_count * block_size)};
        BOOST_REQUIRE(spool);
        std::vector<GovernancePageSnapshotEntry> entries;
        entries.reserve(block_count);
        CGovernancePageViewHasher hasher{uint256{}, block_count};
        // Synthetic storage blocks exercise the spill boundary without
        // constructing oversized governance objects or network messages.
        std::vector<unsigned char> payload(block_size);
        for (uint32_t i{0}; i < block_count; ++i) {
            std::fill(payload.begin(), payload.end(), static_cast<unsigned char>(i));
            const auto offset{spool->Append(payload)};
            BOOST_REQUIRE(offset);
            const CInv inv{MSG_GOVERNANCE_OBJECT, uint256{static_cast<uint8_t>(i + 1)}};
            BOOST_REQUIRE(hasher.Append(inv));
            entries.push_back({inv, {}, *offset, block_size});
        }
        const auto view{hasher.Finalize()};
        BOOST_REQUIRE(view);
        const std::size_t resident{
            sizeof(GovernancePageImmutableSnapshot) +
            GovernancePagePayloadSpool::ResidentBytes() +
            entries.capacity() * sizeof(GovernancePageSnapshotEntry)};
        GovernancePageSnapshotReservation reservation{budget};
        BOOST_REQUIRE(reservation.Reserve(resident));
        const auto snapshot{GovernancePageImmutableSnapshot::Create(
            std::move(reservation), /*instance_id=*/1,
            /*validation_context_epoch=*/1, uint256{}, *view,
            std::move(entries), spool)};
        BOOST_REQUIRE(snapshot);
        BOOST_CHECK_GT(budget->Spooled(), MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES);
        BOOST_CHECK_LT(snapshot->RetainedBytes(), budget->Spooled());
        BOOST_CHECK_EQUAL(snapshot->RetainedBytes(), resident);
        BOOST_CHECK(!spool->Append(payload));
        spool.reset();
        std::fill(payload.begin(), payload.end(), 0xff);
        for (uint32_t i{0}; i < block_count; ++i) {
            BOOST_REQUIRE(snapshot->ReadPayload(i, payload));
            BOOST_CHECK_EQUAL(payload.size(), block_size);
            BOOST_CHECK_EQUAL(snapshot->Entries()[i].PayloadSize(), payload.size());
            BOOST_CHECK(snapshot->Entries()[i].inv.hash == uint256{static_cast<uint8_t>(i + 1)});
            BOOST_CHECK(std::all_of(payload.begin(), payload.end(),
                [i](unsigned char value) { return value == i; }));
        }
        BOOST_CHECK(!snapshot->ReadPayload(block_count, payload));
        BOOST_CHECK(payload.empty());
    }
    BOOST_CHECK_EQUAL(budget->Retained(), 0U);
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);

    BOOST_REQUIRE(budget->ReserveSpooled(GovernancePageSnapshotBudget::MAX_SPOOLED_BYTES));
    const std::vector<unsigned char> one_byte{1};
    BOOST_CHECK(!GovernancePagePayloadSpool::Create(budget, one_byte.size()));
    budget->ReleaseSpooled(GovernancePageSnapshotBudget::MAX_SPOOLED_BYTES);
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);
}

BOOST_AUTO_TEST_CASE(governance_spool_reserves_one_large_scope_beyond_normal_pool)
{
    constexpr std::size_t normal_limit{1ULL << 20};
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>(normal_limit)};
    std::vector<unsigned char> payload(2 * normal_limit);
    for (std::size_t i{0}; i < payload.size(); ++i) {
        payload[i] = static_cast<unsigned char>(i);
    }
    {
        auto large{GovernancePagePayloadSpool::Create(budget, payload.size())};
        BOOST_REQUIRE(large);
        BOOST_CHECK_EQUAL(budget->Spooled(), payload.size());
        BOOST_CHECK(!GovernancePagePayloadSpool::Create(budget, payload.size()));

        // The one large generation does not consume the normal pool, while
        // a second large generation waits for the first reservation to end.
        auto regular{GovernancePagePayloadSpool::Create(budget, normal_limit)};
        BOOST_REQUIRE(regular);
        BOOST_CHECK_EQUAL(budget->Spooled(), payload.size() + normal_limit);
        BOOST_CHECK(!GovernancePagePayloadSpool::Create(budget, 1));
        const auto offset{large->Append(payload)};
        BOOST_REQUIRE(offset);
        BOOST_CHECK_EQUAL(*offset, 0U);
        BOOST_CHECK(!large->Contains(*offset, payload.size()));
        BOOST_REQUIRE(large->Seal());
        const auto regular_offset{regular->Append(
            Span<const unsigned char>{payload.data(), normal_limit})};
        BOOST_REQUIRE(regular_offset);
        BOOST_REQUIRE(regular->Seal());
        std::vector<unsigned char> normal_payload;
        BOOST_REQUIRE(regular->Read(*regular_offset, normal_limit, normal_payload));
        BOOST_CHECK(std::equal(normal_payload.begin(), normal_payload.end(), payload.begin()));

        const CInv inv{MSG_GOVERNANCE_OBJECT, uint256{90}};
        const auto view{ComputeGovernancePageViewHash({}, {inv})};
        BOOST_REQUIRE(view);
        std::vector<GovernancePageSnapshotEntry> entries{
            {inv, {}, *offset, static_cast<uint32_t>(payload.size())}};
        GovernancePageSnapshotReservation reservation{budget};
        BOOST_REQUIRE(reservation.Reserve(
            sizeof(GovernancePageImmutableSnapshot) +
            GovernancePagePayloadSpool::ResidentBytes() +
            entries.capacity() * sizeof(GovernancePageSnapshotEntry)));
        const auto snapshot{GovernancePageImmutableSnapshot::Create(
            std::move(reservation), /*instance_id=*/1,
            /*validation_context_epoch=*/1, {}, *view, std::move(entries), large)};
        BOOST_REQUIRE(snapshot);
        large.reset();
        std::vector<unsigned char> exact;
        BOOST_REQUIRE(snapshot->ReadPayload(0, exact));
        BOOST_CHECK(exact == payload);
        BOOST_CHECK_LT(snapshot->RetainedBytes(), payload.size());
    }
    BOOST_CHECK_EQUAL(budget->Retained(), 0U);
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);

    // A partial write cannot publish a snapshot or strand its whole-scope
    // reservation. Destruction also releases reservations with no writes.
    auto incomplete{GovernancePagePayloadSpool::Create(budget, payload.size())};
    BOOST_REQUIRE(incomplete);
    BOOST_REQUIRE(incomplete->Append(
        Span<const unsigned char>{payload.data(), normal_limit}));
    BOOST_CHECK(!incomplete->Seal());
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);
    {
        const auto retry{GovernancePagePayloadSpool::Create(budget, payload.size())};
        BOOST_REQUIRE(retry);
        BOOST_CHECK_EQUAL(budget->Spooled(), payload.size());
    }
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);
}

BOOST_AUTO_TEST_CASE(governance_spooled_metadata_reservation_is_exclusive_and_grows)
{
    constexpr std::size_t normal_limit{1024};
    constexpr uint32_t count{100};
    constexpr std::size_t growth{128};
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>(
        /*max_spooled_bytes=*/1ULL << 20, /*max_retained_bytes=*/normal_limit)};
    {
        auto spool{GovernancePagePayloadSpool::Create(budget, count)};
        BOOST_REQUIRE(spool);
        std::vector<GovernancePageSnapshotEntry> entries;
        entries.reserve(count);
        CGovernancePageViewHasher hasher{{}, count};
        for (uint32_t i{0}; i < count; ++i) {
            const std::array<unsigned char, 1> payload{static_cast<unsigned char>(i)};
            const auto offset{spool->Append(payload)};
            BOOST_REQUIRE(offset);
            const CInv inv{MSG_GOVERNANCE_OBJECT, uint256{static_cast<uint8_t>(i + 1)}};
            BOOST_REQUIRE(hasher.Append(inv));
            entries.push_back({inv, {}, *offset, 1});
        }
        const auto view{hasher.Finalize()};
        BOOST_REQUIRE(view);
        const std::size_t resident{
            sizeof(GovernancePageImmutableSnapshot) +
            GovernancePagePayloadSpool::ResidentBytes() +
            entries.capacity() * sizeof(GovernancePageSnapshotEntry)};
        BOOST_REQUIRE_GT(resident, normal_limit);
        GovernancePageSnapshotReservation reservation{budget};
        BOOST_CHECK(!reservation.Reserve(resident));
        BOOST_REQUIRE(reservation.Reserve(resident, /*allow_oversized_metadata=*/true));
        BOOST_REQUIRE(reservation.Reserve(growth));
        const std::size_t total{resident + growth};
        BOOST_CHECK_EQUAL(reservation.Reserved(), total);
        BOOST_CHECK_EQUAL(budget->Retained(), total);

        // A metadata lease can grow without taking ordinary resident quota.
        // Its exclusive ownership must survive publication into a snapshot.
        GovernancePageSnapshotReservation regular{budget};
        BOOST_REQUIRE(regular.Reserve(normal_limit));
        BOOST_CHECK(!regular.Reserve(1));
        BOOST_CHECK_EQUAL(budget->Retained(), total + normal_limit);
        GovernancePageSnapshotReservation blocked{budget};
        BOOST_CHECK(!blocked.Reserve(resident, /*allow_oversized_metadata=*/true));
        auto snapshot{GovernancePageImmutableSnapshot::Create(
            std::move(reservation), /*instance_id=*/1,
            /*validation_context_epoch=*/1, {}, *view, std::move(entries), spool)};
        BOOST_REQUIRE(snapshot);
        BOOST_CHECK_EQUAL(snapshot->RetainedBytes(), total);
        spool.reset();
        BOOST_CHECK(!blocked.Reserve(resident, /*allow_oversized_metadata=*/true));
        for (uint32_t i{0}; i < count; ++i) {
            std::vector<unsigned char> payload;
            BOOST_REQUIRE(snapshot->ReadPayload(i, payload));
            BOOST_REQUIRE_EQUAL(payload.size(), 1U);
            BOOST_CHECK_EQUAL(payload.front(), i);
        }
        snapshot.reset();
        BOOST_CHECK_EQUAL(budget->Retained(), normal_limit);
        BOOST_CHECK_EQUAL(budget->Spooled(), 0U);

        // The released lease is immediately reusable, and an unpublished
        // reservation rolls back its initial amount plus subsequent growth.
        BOOST_REQUIRE(blocked.Reserve(resident, /*allow_oversized_metadata=*/true));
        BOOST_REQUIRE(blocked.Reserve(growth));
        BOOST_CHECK_EQUAL(budget->Retained(), total + normal_limit);
    }
    BOOST_CHECK_EQUAL(budget->Retained(), 0U);
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);
}

BOOST_AUTO_TEST_CASE(governance_spooled_metadata_promotes_with_scratch_growth)
{
    constexpr std::size_t normal_limit{1024};
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>(
        /*max_spooled_bytes=*/1ULL << 20, /*max_retained_bytes=*/normal_limit)};
    {
        GovernancePageSnapshotReservation scope{budget};
        BOOST_REQUIRE(scope.Reserve(normal_limit));
        BOOST_CHECK(!scope.Reserve(1));
        {
            GovernancePageSnapshotReservation competing{budget};
            BOOST_REQUIRE(competing.Reserve(normal_limit + 1, true));
            // A failed promotion preserves the original normal reservation.
            BOOST_CHECK(!scope.Reserve(1, true));
            BOOST_CHECK_EQUAL(scope.Reserved(), normal_limit);
            BOOST_CHECK(!scope.IsOversizedMetadata());
            BOOST_CHECK_EQUAL(budget->Retained(), 2 * normal_limit + 1);
        }
        BOOST_REQUIRE(scope.Reserve(1, true));
        BOOST_CHECK(scope.IsOversizedMetadata());
        BOOST_CHECK_EQUAL(scope.Reserved(), normal_limit + 1);
        BOOST_CHECK_EQUAL(budget->Retained(), normal_limit + 1);
        GovernancePageSnapshotReservation regular{budget};
        BOOST_REQUIRE(regular.Reserve(normal_limit));
        BOOST_CHECK_EQUAL(budget->Retained(), 2 * normal_limit + 1);
    }
    BOOST_CHECK_EQUAL(budget->Retained(), 0U);
}

BOOST_AUTO_TEST_CASE(governance_vote_pages_spill_complete_wire_snapshot)
{
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>()};
    {
        CGovernanceObjectVoteFile votes;
        const uint256 parent{uint256{80}};
        GovernanceAuthorization authorization;
        authorization.signed_height = 1;
        authorization.signed_block_hash = uint256{81};
        authorization.pro_tx_hash = uint256{82};
        authorization.global_key_version = 1;
        authorization.signature[0] = 1;
        std::vector<unsigned char> signature;
        BOOST_REQUIRE(EncodeGovernanceAuthorization(authorization, signature));
        // Model stored fixed-width authorizations through the local vote-file
        // seam. Cryptographic admission is covered by the authorization tests.
        const std::size_t count{MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES / signature.size() + 1};
        BOOST_REQUIRE_LT(count, 43'200U);
        for (std::size_t i{0}; i < count; ++i) {
            uint256 collateral;
            WriteLE64(collateral.begin(), i + 1);
            CGovernanceVote vote{COutPoint{collateral, 0}, parent,
                                 VOTE_SIGNAL_VALID, VOTE_OUTCOME_YES};
            vote.SetTime(100);
            vote.SetSignature(signature);
            votes.AddVote(vote);
        }
        const auto wire_size{votes.GetPageSnapshotRetainedBytes()};
        BOOST_REQUIRE(wire_size);
        BOOST_REQUIRE_GT(*wire_size, MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES);

        // Exhausting file capacity leaves this generation retryable and
        // releases its provisional resident-memory reservation.
        BOOST_REQUIRE(budget->ReserveSpooled(GovernancePageSnapshotBudget::MAX_SPOOLED_BYTES));
        BOOST_CHECK(!votes.GetPageSnapshot(parent, budget, 1, 1));
        BOOST_CHECK_EQUAL(budget->Retained(), 0U);
        budget->ReleaseSpooled(GovernancePageSnapshotBudget::MAX_SPOOLED_BYTES);
        const auto snapshot{votes.GetPageSnapshot(parent, budget, 2, 1)};
        BOOST_REQUIRE(snapshot);
        BOOST_REQUIRE_EQUAL(snapshot->TotalCount(), count);
        BOOST_CHECK_GT(budget->Spooled(), MAX_GOVERNANCE_PAGE_SNAPSHOT_BYTES);
        BOOST_CHECK_LT(snapshot->RetainedBytes(), budget->Spooled());
        CGovernancePageViewHasher hasher{parent, snapshot->TotalCount()};
        for (std::size_t i{0}; i < count; ++i) {
            const auto& entry{snapshot->Entries()[i]};
            BOOST_REQUIRE(hasher.Append(entry.inv));
            BOOST_CHECK(entry.payload.empty());
            std::vector<unsigned char> payload;
            BOOST_REQUIRE(snapshot->ReadPayload(i, payload));
            CDataStream wire{Span<const uint8_t>{payload}, SER_NETWORK,
                             GOVERNANCE_PAGE_PROTO_VERSION};
            CGovernanceVote decoded;
            wire >> decoded;
            const auto original{votes.GetVote(entry.inv.hash)};
            BOOST_REQUIRE(original);
            BOOST_CHECK(decoded.HasSameWireEncoding(*original));
            BOOST_CHECK(wire.empty());
        }
        const auto view{hasher.Finalize()};
        BOOST_REQUIRE(view);
        BOOST_CHECK(*view == snapshot->ViewId());
        std::vector<unsigned char> original_payload;
        BOOST_REQUIRE(snapshot->ReadPayload(0, original_payload));
        votes.RemoveVotes({snapshot->Entries().front().inv.hash});
        const auto changed{votes.GetPageSnapshot(parent, budget, 3, 2)};
        BOOST_REQUIRE(changed);
        BOOST_CHECK_EQUAL(changed->TotalCount(), count - 1);
        BOOST_CHECK_EQUAL(changed->ValidationContextEpoch(), 2U);
        BOOST_CHECK(changed->ViewId() != snapshot->ViewId());
        BOOST_CHECK_EQUAL(snapshot->TotalCount(), count);
        std::vector<unsigned char> retained_payload;
        BOOST_REQUIRE(snapshot->ReadPayload(0, retained_payload));
        BOOST_CHECK(retained_payload == original_payload);
    }
    BOOST_CHECK_EQUAL(budget->Retained(), 0U);
    BOOST_CHECK_EQUAL(budget->Spooled(), 0U);
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

BOOST_AUTO_TEST_CASE(retained_vote_wires_have_one_active_representative)
{
    const uint256 parent{uint256{83}};
    const COutPoint voter{uint256{84}, 0};
    const COutPoint unrelated_voter{uint256{85}, 0};
    CGovernanceVote branch_a{
        voter, parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    branch_a.SetTime(100);
    branch_a.SetSignature(std::vector<unsigned char>{1, 2, 3});
    CGovernanceVote branch_b{branch_a};
    branch_b.SetSignature(std::vector<unsigned char>{4, 5, 6});
    BOOST_REQUIRE(branch_a.GetHash() == branch_b.GetHash());
    BOOST_REQUIRE(!branch_a.HasSameWireEncoding(branch_b));
    CGovernanceVote unrelated{
        unrelated_voter, parent, VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_NO};
    unrelated.SetTime(100);

    CGovernanceObjectVoteFile votes;
    votes.AddVote(branch_a, /*retain_replaced=*/true);
    votes.AddVote(unrelated, /*retain_replaced=*/true);
    const uint64_t original_bytes{votes.GetSerializedVoteBytes()};
    const auto budget{std::make_shared<GovernancePageSnapshotBudget>()};
    const auto original_page{votes.GetPageSnapshot(
        parent, budget, /*instance_id=*/10,
        /*validation_context_epoch=*/10)};
    BOOST_REQUIRE(original_page);

    // A branch change hides A without dropping its authenticated wire form.
    const auto deactivated{votes.UpdateActiveVotes(voter, {})};
    BOOST_CHECK(deactivated.contains(branch_a.GetHash()));
    BOOST_CHECK(!votes.HasVote(branch_a.GetHash()));
    BOOST_CHECK(!votes.GetVote(branch_a.GetHash()));
    BOOST_CHECK(!votes.GetVoteSerializedSizeUpperBound(
        branch_a.GetHash(), PROTOCOL_VERSION));
    CDataStream hidden{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK(!votes.SerializeVoteToStream(branch_a.GetHash(), hidden));
    BOOST_CHECK(hidden.empty());
    BOOST_CHECK_EQUAL(votes.GetVoteCount(), 1);
    BOOST_CHECK(votes.HasStoredVoteFromMasternode(voter));
    BOOST_CHECK(!votes.HasVoteFromMasternode(voter));
    BOOST_CHECK(votes.HasVote(unrelated.GetHash()));
    BOOST_CHECK_EQUAL(votes.GetSerializedVoteBytes(), original_bytes);

    const uint64_t projected{
        votes.ProjectedSerializedVoteBytes(branch_b,
                                           /*retain_replaced=*/true)};
    BOOST_REQUIRE_GT(projected, original_bytes);
    votes.AddVote(branch_b, /*retain_replaced=*/true);
    BOOST_CHECK_EQUAL(votes.GetSerializedVoteBytes(), projected);
    votes.AddVote(branch_b, /*retain_replaced=*/true);
    BOOST_CHECK_EQUAL(votes.GetSerializedVoteBytes(), projected);

    const auto select_wire = [](CGovernanceObjectVoteFile& file,
                                const CGovernanceVote& selected) {
        std::vector<const CGovernanceVote*> selection;
        file.ForEachStoredVote([&](const CGovernanceVote& stored) {
            if (stored.HasSameWireEncoding(selected)) {
                selection.push_back(&stored);
            }
            return true;
        });
        BOOST_REQUIRE_EQUAL(selection.size(), 1U);
        return file.UpdateActiveVotes(
            selected.GetMasternodeOutpoint(), selection);
    };
    select_wire(votes, branch_b);
    BOOST_REQUIRE(votes.GetVote(branch_b.GetHash()));
    BOOST_CHECK(votes.GetVote(branch_b.GetHash())->HasSameWireEncoding(
        branch_b));
    BOOST_CHECK_EQUAL(votes.GetVoteCount(), 2);
    const auto branch_b_page{votes.GetPageSnapshot(
        parent, budget, /*instance_id=*/11,
        /*validation_context_epoch=*/10)};
    BOOST_REQUIRE(branch_b_page);
    BOOST_CHECK(branch_b_page != original_page);
    // The inventory view is unchanged, but its exact payload generation is new.
    BOOST_CHECK(branch_b_page->ViewId() == original_page->ViewId());
    const auto check_page_wire = [&](const auto& page,
                                     const CGovernanceVote& expected) {
        bool found{false};
        for (const auto& entry : page->Entries()) {
            if (entry.inv.hash != expected.GetHash()) continue;
            CDataStream stream{
                Span<const uint8_t>{entry.payload}, SER_NETWORK,
                GOVERNANCE_PAGE_PROTO_VERSION};
            CGovernanceVote decoded;
            stream >> decoded;
            BOOST_CHECK(decoded.HasSameWireEncoding(expected));
            BOOST_CHECK(stream.empty());
            found = true;
        }
        BOOST_CHECK(found);
    };
    check_page_wire(original_page, branch_a);
    check_page_wire(branch_b_page, branch_b);

    const auto reactivated{select_wire(votes, branch_a)};
    BOOST_CHECK(reactivated.contains(branch_a.GetHash()));
    BOOST_CHECK_EQUAL(votes.GetSerializedVoteBytes(), projected);
    const CGovernanceObjectVoteFile copied{votes};
    BOOST_REQUIRE(copied.GetVote(branch_a.GetHash()));
    BOOST_CHECK(copied.GetVote(branch_a.GetHash())->HasSameWireEncoding(
        branch_a));
    BOOST_CHECK_EQUAL(copied.GetSerializedVoteBytes(), projected);

    CGovernanceObjectVoteFile inactive{votes};
    (void)inactive.UpdateActiveVotes(voter, {});
    const CGovernanceObjectVoteFile inactive_copy{inactive};
    CGovernanceObjectVoteFile assigned;
    assigned.AddVote(branch_b);
    assigned = inactive;
    for (const auto* file : std::array<const CGovernanceObjectVoteFile*, 2>{
             &inactive_copy, &assigned}) {
        BOOST_CHECK(!file->HasVote(branch_a.GetHash()));
        BOOST_CHECK(file->HasStoredVoteFromMasternode(voter));
        BOOST_CHECK(file->HasVote(unrelated.GetHash()));
        BOOST_CHECK_EQUAL(file->GetVoteCount(), 1);
        BOOST_CHECK_EQUAL(file->GetSerializedVoteBytes(), projected);
    }
    select_wire(assigned, branch_b);
    BOOST_REQUIRE(assigned.GetVote(branch_b.GetHash()));
    BOOST_CHECK(assigned.GetVote(branch_b.GetHash())->HasSameWireEncoding(branch_b));

    // Same logical hashes must survive the legacy list serialization together.
    CDataStream disk{SER_DISK, PROTOCOL_VERSION};
    disk << votes;
    CGovernanceObjectVoteFile reloaded;
    disk >> reloaded;
    BOOST_CHECK(disk.empty());
    std::size_t stored_count{0};
    reloaded.ForEachStoredVote([&](const CGovernanceVote&) {
        ++stored_count;
        return true;
    });
    BOOST_CHECK_EQUAL(stored_count, 3U);
    BOOST_CHECK_EQUAL(reloaded.GetSerializedVoteBytes(), projected);
    select_wire(reloaded, branch_a);
    BOOST_REQUIRE(reloaded.GetVote(branch_a.GetHash()));
    BOOST_CHECK(reloaded.GetVote(branch_a.GetHash())->HasSameWireEncoding(
        branch_a));
    select_wire(reloaded, branch_b);
    BOOST_REQUIRE(reloaded.GetVote(branch_b.GetHash()));
    BOOST_CHECK(reloaded.GetVote(branch_b.GetHash())->HasSameWireEncoding(
        branch_b));
}

BOOST_FIXTURE_TEST_CASE(
    retained_trigger_and_proposal_votes_reconcile_wire_variants_and_supersession,
    BasicTestingSetup)
{
    const int activation_height{Params().GetConsensus().DIP0003Height};
    BOOST_REQUIRE_GT(activation_height, 0);
    ScopedPQActivation activation{activation_height};
    std::array<CBlockIndex, 2> common;
    std::array<uint256, 2> common_hashes;
    BuildBranch(common, common_hashes, nullptr, activation_height - 1,
                0x70, /*build_skip=*/false);
    std::array<CBlockIndex, 2> branch_a;
    std::array<uint256, 2> branch_a_hashes;
    BuildBranch(branch_a, branch_a_hashes, &common.back(),
                activation_height + 1, 0x71, /*build_skip=*/false);
    std::array<CBlockIndex, 2> branch_b;
    std::array<uint256, 2> branch_b_hashes;
    BuildBranch(branch_b, branch_b_hashes, &common.back(),
                activation_height + 1, 0x72, /*build_skip=*/false);

    const uint256 pro_tx_hash{uint256{86}};
    const COutPoint collateral{uint256{87}, 0};
    auto signing_secret{DeterministicGlobalKey(0x73)};
    const auto signing_key{GlobalKeyFor(
        signing_secret, pro_tx_hash, /*key_version=*/1,
        static_cast<uint32_t>(activation_height))};
    const auto operator_state{
        CurrentOperatorState(pro_tx_hash, signing_key, /*active=*/true)};
    const VotingKeyRecord voting_key{
        signing_key.public_key, signing_key.key_version, activation_height};
    for (const int object_type : {GOVERNANCE_OBJECT_TRIGGER, GOVERNANCE_OBJECT_PROPOSAL}) {
    const std::string object_data = object_type == GOVERNANCE_OBJECT_TRIGGER
        ? "7b2274797065223a327d" : "7b2274797065223a317d";
    CGovernanceObject object{
        uint256{}, /*revision=*/1, /*time=*/100, uint256{},
        object_data};
    BOOST_REQUIRE_EQUAL(object.GetObjectType(), object_type);
    auto& vote_file{const_cast<CGovernanceObjectVoteFile&>(
        object.GetVoteFile())};
    const auto make_vote = [&](const CBlockIndex& signing_block,
                               int64_t timestamp,
                               vote_outcome_enum_t outcome) {
        CGovernanceVote vote{
            collateral, object.GetHash(), VOTE_SIGNAL_FUNDING, outcome};
        vote.SetTime(timestamp);
        GovernanceAuthorization authorization;
        authorization.signed_height = signing_block.nHeight;
        authorization.signed_block_hash = signing_block.GetBlockHash();
        authorization.pro_tx_hash = pro_tx_hash;
        authorization.global_key_version = signing_key.key_version;
        // Reconciliation handles previously admitted signatures and repeats
        // only their exact branch/current-key checks, as on cache startup.
        authorization.signature[0] = 1;
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(EncodeGovernanceAuthorization(authorization, encoded));
        vote.SetSignature(encoded);
        return vote;
    };
    const auto reconcile = [&](CGovernanceObject& target,
                                const CBlockIndex& tip) {
        const auto list{CurrentMNList(tip, pro_tx_hash, collateral, voting_key)};
        const auto snapshot{CurrentRegistrySnapshot(tip, operator_state)};
        return target.RemoveInvalidPQVotes(tip, list, snapshot);
    };
    const auto check_selected = [&](const CGovernanceObject& target,
                                     const CGovernanceVote& expected) {
        const auto selected{target.GetVoteFile().GetVote(expected.GetHash())};
        BOOST_REQUIRE(selected);
        BOOST_CHECK(selected->HasSameWireEncoding(expected));
        BOOST_CHECK_EQUAL(target.GetVoteFile().GetVoteCount(), 1);
        vote_rec_t current;
        BOOST_REQUIRE(target.GetCurrentMNVotes(collateral, current));
        const auto instance{current.mapInstances.find(VOTE_SIGNAL_FUNDING)};
        BOOST_REQUIRE(instance != current.mapInstances.end());
        BOOST_CHECK_EQUAL(instance->second.eOutcome, expected.GetOutcome());
        BOOST_CHECK_EQUAL(instance->second.nCreationTime,
                          expected.GetTimestamp());
    };

    const auto a{make_vote(branch_a.front(), 100, VOTE_OUTCOME_YES)};
    const auto b{make_vote(branch_b.front(), 100, VOTE_OUTCOME_YES)};
    BOOST_REQUIRE(a.GetHash() == b.GetHash());
    vote_file.AddVote(a, /*retain_replaced=*/true);
    reconcile(object, branch_a.back());
    check_selected(object, a);
    const uint64_t one_wire_bytes{vote_file.GetSerializedVoteBytes()};

    reconcile(object, branch_b.back());
    BOOST_CHECK_EQUAL(object.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 0);
    BOOST_CHECK_EQUAL(vote_file.GetVoteCount(), 0);
    BOOST_CHECK_EQUAL(vote_file.GetSerializedVoteBytes(), one_wire_bytes);
    vote_file.AddVote(b, /*retain_replaced=*/true);
    reconcile(object, branch_b.back());
    check_selected(object, b);
    BOOST_CHECK_EQUAL(object.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 1);
    const uint64_t both_wire_bytes{vote_file.GetSerializedVoteBytes()};
    BOOST_CHECK_EQUAL(both_wire_bytes, 2 * one_wire_bytes);
    const auto switched{reconcile(object, branch_a.back())};
    BOOST_CHECK(switched.contains(a.GetHash()));
    check_selected(object, a);

    reconcile(object, common.back());
    BOOST_CHECK_EQUAL(object.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 0);
    BOOST_CHECK_EQUAL(vote_file.GetVoteCount(), 0);
    BOOST_REQUIRE(object.NextPQAuthorizationHeight(common.back().nHeight));
    BOOST_CHECK_EQUAL(*object.NextPQAuthorizationHeight(common.back().nHeight),
                      branch_a.front().nHeight);
    CDataStream disk{SER_DISK, PROTOCOL_VERSION};
    disk << object;
    CGovernanceObject reloaded;
    disk >> reloaded;
    BOOST_CHECK(disk.empty());
    reconcile(reloaded, common.back());
    BOOST_CHECK_EQUAL(reloaded.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 0);
    BOOST_CHECK_EQUAL(reloaded.GetVoteFile().GetSerializedVoteBytes(),
                      both_wire_bytes);
    reconcile(reloaded, branch_a.back());
    check_selected(reloaded, a);
    reconcile(reloaded, branch_b.back());
    check_selected(reloaded, b);

    // A newer B vote supersedes the A vote, but cannot erase the earlier
    // accepted choice needed when returning to A. Equal timestamps use the
    // same outcome tie break as ordinary vote admission.
    for (const int64_t replacement_time : {int64_t{100}, int64_t{101}}) {
        CGovernanceObject superseded{
            uint256{}, /*revision=*/1, /*time=*/100, uint256{},
            object_data};
        auto& retained{const_cast<CGovernanceObjectVoteFile&>(
            superseded.GetVoteFile())};
        const auto original{make_vote(common.back(), 100, VOTE_OUTCOME_YES)};
        const auto replacement{
            make_vote(branch_b.front(), replacement_time, VOTE_OUTCOME_NO)};
        retained.AddVote(original, /*retain_replaced=*/true);
        retained.AddVote(replacement, /*retain_replaced=*/true);
        BOOST_CHECK_EQUAL(retained.GetVoteCount(), 1);
        BOOST_CHECK(!retained.HasVote(original.GetHash()));
        BOOST_REQUIRE(retained.GetVote(replacement.GetHash()));
        BOOST_CHECK(retained.GetVote(replacement.GetHash())->HasSameWireEncoding(
            replacement));
        const uint64_t retained_bytes{retained.GetSerializedVoteBytes()};
        reconcile(superseded, branch_b.back());
        check_selected(superseded, replacement);
        BOOST_CHECK_EQUAL(superseded.GetAbsoluteNoCount(VOTE_SIGNAL_FUNDING), 1);
        reconcile(superseded, branch_a.back());
        check_selected(superseded, original);
        BOOST_CHECK_EQUAL(superseded.GetAbsoluteYesCount(VOTE_SIGNAL_FUNDING), 1);
        BOOST_CHECK_EQUAL(superseded.GetNoCount(VOTE_SIGNAL_FUNDING), 0);
        BOOST_CHECK_EQUAL(retained.GetSerializedVoteBytes(), retained_bytes);
    }
    }
}

BOOST_AUTO_TEST_SUITE_END()
