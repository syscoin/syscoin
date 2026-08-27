// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_registry.h>

#include <consensus/params.h>
#include <crypto/slhdsa/slhdsa.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <key.h>
#include <llmq/pq_global_auth.h>
#include <messagesigner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace llmq::pq;

namespace {

uint256 NonNullHash(uint32_t value)
{
    uint256 hash;
    hash.begin()[0] = value & 0xff;
    hash.begin()[1] = (value >> 8) & 0xff;
    hash.begin()[2] = (value >> 16) & 0xff;
    hash.begin()[3] = (value >> 24) & 0xff;
    if (hash.IsNull()) hash.begin()[0] = 1;
    return hash;
}

PQRegistryConfig Config()
{
    PQRegistryConfig config;
    config.preparation_height = 1000;
    config.schedule.epoch_origin = 1440;
    config.registration_cutoff_blocks = 144;
    config.future_horizon_epochs = 8;
    return config;
}

PQRegistryConfig FastConfig()
{
    auto config{Config()};
    // Epoch zero freezes one block after preparation. This keeps cutoff and
    // historical-root tests fast without changing the consensus cadence.
    config.preparation_height = 1295;
    return config;
}

DBParams MemoryDB(uint32_t id)
{
    return DBParams{
        .path = fs::PathFromString(
            "testdb_pq_registry_roots_" + std::to_string(id)),
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
}

slhdsa::SecretKey DeterministicKey(uint8_t offset)
{
    slhdsa::KeyGenerationSeed seed;
    for (std::size_t i{0}; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(i + offset);
    }
    auto key{slhdsa::GenerateSecretKey(seed)};
    BOOST_REQUIRE(key);
    return std::move(*key);
}

GlobalSignature SignDigest(const slhdsa::SecretKey& key,
                           GlobalAuthPurpose purpose,
                           const uint256& digest)
{
    GlobalSignature signature;
    BOOST_REQUIRE(slhdsa::SignDeterministic(
        key, std::span<const uint8_t>{digest.begin(), digest.size()},
        GetGlobalAuthContext(purpose), signature));
    return signature;
}

ChildKeyTreeCommitment CommitmentAt(const PQRegistryConfig& config,
                                    int32_t height,
                                    uint32_t generation,
                                    uint32_t tag)
{
    const auto view{DeriveOperatorKeyScheduleView(
        config.schedule, height, config.registration_cutoff_blocks,
        config.future_horizon_epochs)};
    BOOST_REQUIRE(view);
    ChildKeyTreeCommitment commitment;
    commitment.generation = generation;
    commitment.first_epoch = view->first_mutable_epoch;
    commitment.tree_id = NonNullHash(50'000 + tag);
    commitment.root = NonNullHash(60'000 + tag);
    BOOST_REQUIRE(commitment.IsStructurallyValid());
    return commitment;
}

GlobalKeyRecord Candidate(const slhdsa::SecretKey& key,
                          uint32_t key_version,
                          const ChildKeyTreeCommitment& commitment)
{
    GlobalKeyRecord candidate;
    candidate.key_version = key_version;
    candidate.child_key_commitment = commitment;
    BOOST_REQUIRE(key.GetPublicKey(candidate.public_key));
    BOOST_REQUIRE(IsGlobalKeyCandidateStructurallyValid(candidate));
    return candidate;
}

CMutableTransaction BaseTransaction(uint32_t id, int32_t version)
{
    CMutableTransaction tx;
    tx.nVersion = version;
    tx.vin.emplace_back(COutPoint{NonNullHash(10'000 + id), id});
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    return tx;
}

CTransactionRef GlobalRegistration(const uint256& genesis,
                                   const uint256& pro_tx_hash,
                                   const slhdsa::SecretKey& key,
                                   const CKey& owner_key,
                                   const ChildKeyTreeCommitment& commitment,
                                   uint32_t id)
{
    CMutableTransaction tx{BaseTransaction(id, PQ_GLOBAL_KEY_TX_VERSION)};
    GlobalKeyTxPayload payload;
    payload.operation = GlobalKeyOperation::INITIAL;
    payload.pro_tx_hash = pro_tx_hash;
    payload.candidate = Candidate(key, /*key_version=*/1, commitment);
    payload.transaction_inputs_hash = CalcTxInputsHash(CTransaction{tx});
    const auto owner_digest{
        GetGlobalOwnerRegistrationAuthorizationHash(genesis, payload)};
    BOOST_REQUIRE(owner_digest);
    std::vector<unsigned char> owner_signature;
    BOOST_REQUIRE(CHashSigner::SignHash(
        *owner_digest, owner_key, owner_signature));
    BOOST_REQUIRE_EQUAL(owner_signature.size(),
                        COMPACT_ECDSA_SIGNATURE_SIZE);
    std::copy(owner_signature.begin(), owner_signature.end(),
              payload.owner_authorization.begin());
    const auto digest{GetGlobalRegistrationAuthorizationHash(
        genesis, pro_tx_hash, payload.candidate,
        payload.transaction_inputs_hash)};
    BOOST_REQUIRE(digest);
    payload.authorization = SignDigest(
        key, GlobalAuthPurpose::GLOBAL_REGISTRATION, *digest);
    SetTxPayload(tx, payload);
    return MakeTransactionRef(std::move(tx));
}

CTransactionRef GlobalRotation(const uint256& genesis,
                               const uint256& pro_tx_hash,
                               const GlobalKeyRecord& current,
                               const slhdsa::SecretKey& current_key,
                               const slhdsa::SecretKey& replacement_key,
                               const ChildKeyTreeCommitment& commitment,
                               uint32_t id)
{
    CMutableTransaction tx{BaseTransaction(id, PQ_GLOBAL_KEY_TX_VERSION)};
    GlobalKeyTxPayload payload;
    payload.operation = GlobalKeyOperation::ROTATE;
    payload.pro_tx_hash = pro_tx_hash;
    payload.candidate = Candidate(
        replacement_key, current.key_version + 1, commitment);
    payload.transaction_inputs_hash = CalcTxInputsHash(CTransaction{tx});
    const auto digest{GetGlobalRotationAuthorizationHash(
        genesis, pro_tx_hash, current, payload.candidate,
        payload.transaction_inputs_hash)};
    BOOST_REQUIRE(digest);
    payload.authorization = SignDigest(
        current_key, GlobalAuthPurpose::GLOBAL_ROTATION, *digest);
    SetTxPayload(tx, payload);
    return MakeTransactionRef(std::move(tx));
}

CTransactionRef GlobalRecovery(const uint256& genesis,
                               const uint256& pro_tx_hash,
                               const GlobalKeyRecord& current,
                               const slhdsa::SecretKey& recovery_key,
                               const CKey& owner_key,
                               const ChildKeyTreeCommitment& commitment,
                               uint32_t id)
{
    CMutableTransaction tx{BaseTransaction(id, PQ_GLOBAL_KEY_TX_VERSION)};
    GlobalKeyTxPayload payload;
    payload.operation = GlobalKeyOperation::INITIAL;
    payload.pro_tx_hash = pro_tx_hash;
    payload.candidate = Candidate(
        recovery_key, current.key_version + 1, commitment);
    payload.transaction_inputs_hash = CalcTxInputsHash(CTransaction{tx});
    const auto owner_digest{
        GetGlobalOwnerRegistrationAuthorizationHash(genesis, payload)};
    BOOST_REQUIRE(owner_digest);
    std::vector<unsigned char> owner_signature;
    BOOST_REQUIRE(CHashSigner::SignHash(
        *owner_digest, owner_key, owner_signature));
    BOOST_REQUIRE_EQUAL(owner_signature.size(),
                        COMPACT_ECDSA_SIGNATURE_SIZE);
    std::copy(owner_signature.begin(), owner_signature.end(),
              payload.owner_authorization.begin());
    const auto digest{GetGlobalRecoveryAuthorizationHash(
        genesis, pro_tx_hash, current, payload.candidate,
        payload.transaction_inputs_hash)};
    BOOST_REQUIRE(digest);
    payload.authorization = SignDigest(
        recovery_key, GlobalAuthPurpose::GLOBAL_REGISTRATION, *digest);
    SetTxPayload(tx, payload);
    return MakeTransactionRef(std::move(tx));
}

CTransactionRef ProviderRevocation(const uint256& genesis,
                                   const uint256& pro_tx_hash,
                                   const GlobalKeyRecord& current,
                                   const slhdsa::SecretKey& current_key,
                                   uint32_t id)
{
    CMutableTransaction tx{
        BaseTransaction(id, SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE)};
    CProUpRevTx payload;
    payload.nVersion = CProUpRevTx::PQ_VERSION;
    payload.proTxHash = pro_tx_hash;
    payload.nReason = CProUpRevTx::REASON_COMPROMISED_KEYS;
    payload.inputsHash = CalcTxInputsHash(CTransaction{tx});
    payload.globalKeyVersion = current.key_version;

    ProviderRevokeAuthorization authorization;
    authorization.payload_version = payload.nVersion;
    authorization.pro_tx_hash = pro_tx_hash;
    authorization.global_key_version = payload.globalKeyVersion;
    authorization.reason = payload.nReason;
    authorization.transaction_inputs_hash = payload.inputsHash;
    const auto digest{GetProviderRevokeAuthorizationHash(
        genesis, current, authorization)};
    BOOST_REQUIRE(digest);
    payload.pqSig = SignDigest(
        current_key, GlobalAuthPurpose::PROVIDER_REVOKE, *digest);
    SetTxPayload(tx, payload);
    return MakeTransactionRef(std::move(tx));
}

CTransactionRef OrdinaryTransaction(uint32_t id)
{
    return MakeTransactionRef(BaseTransaction(id, /*version=*/2));
}

CTransactionRef CorruptAuthorization(const CTransactionRef& transaction)
{
    CMutableTransaction corrupted{*transaction};
    GlobalKeyTxPayload payload;
    BOOST_REQUIRE(GetTxPayload(corrupted, payload));
    payload.authorization[payload.authorization.size() / 2] ^= 0x5a;
    SetTxPayload(corrupted, payload);
    return MakeTransactionRef(std::move(corrupted));
}

CBlock Block(const uint256& previous,
             uint32_t id,
             std::vector<CTransactionRef> transactions)
{
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = previous;
    block.hashMerkleRoot = NonNullHash(20'000 + id);
    block.nTime = 1'700'000'000 + id;
    block.nBits = 0x207fffff;
    block.nNonce = id;
    block.vtx = std::move(transactions);
    return block;
}

PQRegistryCallbacks Members(const uint256& genesis_hash,
                            std::vector<uint256> before,
                            std::vector<uint256> after,
                            const CKeyID& owner_key_id,
                            bool owner_authorized = true)
{
    const auto contains = [](const std::vector<uint256>& members,
                             const uint256& hash) {
        return std::find(members.begin(), members.end(), hash) !=
               members.end();
    };
    return PQRegistryCallbacks{
        [before = std::move(before), contains](const uint256& hash) {
            return contains(before, hash);
        },
        [after = std::move(after), contains](const uint256& hash) {
            return contains(after, hash);
        },
        [=](const GlobalKeyTxPayload& payload,
            const uint256& authorization_hash) {
            const auto expected{
                GetGlobalOwnerRegistrationAuthorizationHash(
                    genesis_hash, payload)};
            return owner_authorized && expected &&
                   *expected == authorization_hash &&
                   VerifyGlobalOwnerRegistrationAuthorization(
                       genesis_hash, payload, owner_key_id);
        },
    };
}

PQRegistryCallbacks Member(const uint256& genesis_hash,
                           const uint256& pro_tx_hash,
                           const CKeyID& owner_key_id,
                           bool exists_after = true,
                           bool owner_authorized = true)
{
    return Members(genesis_hash, {pro_tx_hash},
                   exists_after ? std::vector<uint256>{pro_tx_hash}
                                : std::vector<uint256>{},
                   owner_key_id, owner_authorized);
}

const OperatorKeyState& OnlyOperator(const PQRegistrySnapshot& snapshot)
{
    BOOST_REQUIRE_EQUAL(snapshot.operator_states.size(), 1U);
    return snapshot.operator_states.front();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_registry_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(configuration_requires_real_preparation_window)
{
    auto config{Config()};
    BOOST_REQUIRE(config.IsValid());
    BOOST_REQUIRE(FastConfig().IsValid());
    config.preparation_height = 1296;
    BOOST_CHECK(!config.IsValid());
    config = Config();
    config.preparation_height = config.schedule.epoch_origin;
    BOOST_CHECK(!config.IsValid());
    config = Config();
    config.future_horizon_epochs = ACTIVE_QUORUMS - 1;
    BOOST_CHECK(!config.IsValid());

    Consensus::Params params{};
    PQRegistryConfig from_consensus;
    BOOST_CHECK(GetPQRegistryConfig(params, from_consensus) ==
                PQRegistryDeploymentResult::DISABLED);
    params.nPQPreparationHeight = 1000;
    BOOST_CHECK(GetPQRegistryConfig(params, from_consensus) ==
                PQRegistryDeploymentResult::INVALID_CONFIGURATION);
    params.DIP0003Height = 500;
    params.nPQLegacyAnchorHeight = 1100;
    params.hashPQLegacyAnchorBlock = NonNullHash(100);
    params.hashPQLegacyMNState = NonNullHash(101);
    params.hashPQLegacyPQRegistryState = NonNullHash(102);
    params.nPQChainLockEpochOrigin = 1440;
    params.nPQRegistrationCutoffBlocks = 144;
    params.nPQFutureHorizonEpochs = 8;
    BOOST_CHECK(GetPQRegistryConfig(params, from_consensus) ==
                PQRegistryDeploymentResult::VALID);
    BOOST_CHECK(from_consensus == Config());
    params.nPQPreparationHeight = params.nPQLegacyAnchorHeight + 1;
    BOOST_CHECK(GetPQRegistryConfig(params, from_consensus) ==
                PQRegistryDeploymentResult::INVALID_CONFIGURATION);
}

BOOST_AUTO_TEST_CASE(read_views_share_state_but_preserve_exact_block_identity)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(301)};
    PQRegistryManager manager(MemoryDB(301), genesis, config);
    PQRegistryError error;

    PQRegistryReadView genesis_view;
    const uint256 genesis_block{NonNullHash(302)};
    BOOST_REQUIRE(manager.GetReadView(
        genesis_block, uint256{}, 0, genesis_view, error));
    BOOST_CHECK(genesis_view.IsValid());
    BOOST_CHECK_EQUAL(genesis_view.Height(), 0);
    BOOST_CHECK(genesis_view.BlockHash() == genesis_block);
    BOOST_CHECK(genesis_view.PreviousBlockHash().IsNull());

    const auto preparation{Block(
        NonNullHash(303), 304, {OrdinaryTransaction(304)})};
    const auto cutoff{Block(
        preparation.GetHash(), 305, {OrdinaryTransaction(305)})};
    const auto steady_a{Block(
        cutoff.GetHash(), 306, {OrdinaryTransaction(306)})};
    const auto steady_b{Block(
        cutoff.GetHash(), 307, {OrdinaryTransaction(307)})};
    const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
    BOOST_REQUIRE(manager.ProcessBlock(
        preparation, config.preparation_height, callbacks, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        cutoff, config.preparation_height + 1, callbacks, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        steady_a, config.preparation_height + 2, callbacks, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        steady_b, config.preparation_height + 2, callbacks, false, error));

    PQRegistryReadView preparation_view;
    PQRegistryReadView cutoff_view;
    PQRegistryReadView steady_a_view;
    PQRegistryReadView steady_b_view;
    BOOST_REQUIRE(manager.GetReadView(
        preparation.GetHash(), preparation.hashPrevBlock,
        config.preparation_height, preparation_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        cutoff.GetHash(), preparation.GetHash(),
        config.preparation_height + 1, cutoff_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        steady_a.GetHash(), cutoff.GetHash(),
        config.preparation_height + 2, steady_a_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        steady_b.GetHash(), cutoff.GetHash(),
        config.preparation_height + 2, steady_b_view, error));

    BOOST_CHECK(!preparation_view.SharesStateWith(cutoff_view));
    BOOST_CHECK(cutoff_view.SharesStateWith(steady_a_view));
    BOOST_CHECK(steady_a_view.SharesStateWith(steady_b_view));
    BOOST_CHECK(steady_a_view.BlockHash() != steady_b_view.BlockHash());
    BOOST_CHECK(steady_a_view.PreviousBlockHash() == cutoff.GetHash());
    BOOST_CHECK(steady_b_view.PreviousBlockHash() == cutoff.GetHash());
    BOOST_CHECK(steady_a_view.ConsensusStateRoot() ==
                steady_b_view.ConsensusStateRoot());

    for (int32_t height{1};
         height <= static_cast<int32_t>(PQ_REGISTRY_SNAPSHOT_CACHE_SIZE + 1);
         ++height) {
        PQRegistryReadView historical;
        BOOST_REQUIRE(manager.GetReadView(
            NonNullHash(400 + height), NonNullHash(399 + height), height,
            historical, error));
    }
    BOOST_CHECK(genesis_view.IsValid());
    BOOST_CHECK(genesis_view.BlockHash() == genesis_block);
}

BOOST_AUTO_TEST_CASE(initial_root_registration_is_branch_keyed_and_check_only_is_pure)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(1)};
    const uint256 pro_tx_hash{NonNullHash(2)};
    const uint256 parent{NonNullHash(3)};
    auto key{DeterministicKey(0)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto commitment{CommitmentAt(config, 1295, 1, 1)};
    const auto registration{GlobalRegistration(
        genesis, pro_tx_hash, key, owner_key, commitment, 2)};
    const auto block{Block(parent, 1,
                           {OrdinaryTransaction(1), registration})};

    PQRegistryManager manager(MemoryDB(1), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ValidateTransaction(
        *registration, parent, 1295,
        Member(genesis, pro_tx_hash, owner_key_id),
        /*check_sigs=*/true, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        block, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        /*fJustCheck=*/true, error));
    PQRegistrySnapshot missing;
    BOOST_CHECK(!manager.GetSnapshot(
        block.GetHash(), parent, 1295, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    BOOST_REQUIRE(manager.ProcessBlock(
        block, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        /*fJustCheck=*/false, error));
    PQRegistrySnapshot snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        block.GetHash(), parent, 1295, snapshot, error));
    const auto& state{OnlyOperator(snapshot)};
    BOOST_CHECK(state.pro_tx_hash == pro_tx_hash);
    BOOST_CHECK(state.HasActiveGlobalKey());
    BOOST_CHECK_EQUAL(state.global_key.activated_height, 1295U);
    BOOST_CHECK(state.global_key.child_key_commitment == commitment);
    BOOST_REQUIRE_EQUAL(snapshot.used_tree_ids.size(), 1U);
    BOOST_REQUIRE_EQUAL(snapshot.block_tree_ids.size(), 1U);
    BOOST_CHECK(snapshot.used_tree_ids.front() == commitment.tree_id);
    BOOST_CHECK(snapshot.block_tree_ids.front() == commitment.tree_id);
    BOOST_CHECK(state.ResolveChildRoot(0).status ==
                ChildRootResolutionStatus::MUTABLE_PRESENT);

    std::vector<uint256> requested{
        pro_tx_hash, NonNullHash(4)};
    std::sort(requested.begin(), requested.end());
    PQRegistryMempoolView mempool_view;
    BOOST_REQUIRE(manager.GetMempoolView(
        block.GetHash(), 1295, requested, mempool_view, error));
    BOOST_CHECK_EQUAL(mempool_view.operator_state_count, 1U);
    BOOST_CHECK_EQUAL(mempool_view.used_tree_id_count, 1U);
    BOOST_CHECK_EQUAL(mempool_view.operators.size(), requested.size());
    BOOST_CHECK_EQUAL(mempool_view.has_next_block_schedule, 1U);
    const auto next_schedule{DeriveOperatorKeyScheduleView(
        config.schedule, 1296, config.registration_cutoff_blocks,
        config.future_horizon_epochs)};
    BOOST_REQUIRE(next_schedule);
    BOOST_CHECK_EQUAL(mempool_view.next_first_mutable_epoch,
                      next_schedule->first_mutable_epoch);
    const auto* current{mempool_view.FindOperator(pro_tx_hash)};
    BOOST_REQUIRE(current);
    BOOST_CHECK_EQUAL(current->state_exists, 1U);
    BOOST_CHECK_EQUAL(current->has_global_key, 1U);
    BOOST_CHECK(current->current_commitment == commitment);
    const auto* absent{mempool_view.FindOperator(NonNullHash(4))};
    BOOST_REQUIRE(absent);
    BOOST_CHECK_EQUAL(absent->state_exists, 0U);
}

BOOST_AUTO_TEST_CASE(per_block_journal_is_async_and_sync_flush_is_a_barrier)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(151)};
    const uint256 parent{NonNullHash(152)};
    const auto block{Block(parent, 153, {OrdinaryTransaction(153)})};
    PQRegistryManager manager(MemoryDB(151), genesis, config);
    PQRegistryError error;

    // SYSCOIN: Connecting an ordinary block must publish its reconstruction
    // link without a synchronous write-through. A later explicit flush is the
    // durability boundary shared with the UTXO best-block marker.
    manager.SnapshotDatabase()
        .FailNextSynchronousWriteThroughForTesting();
    BOOST_REQUIRE(manager.ProcessBlock(
        block, config.preparation_height,
        Members(genesis, {}, {}, CKeyID{}), /*fJustCheck=*/false, error));
    BOOST_CHECK_EQUAL(
        manager.SnapshotDatabase().GetReadWriteCacheSize(), 0U);
    BOOST_CHECK_EQUAL(
        manager.SnapshotDatabase().CountPersistedEntries(), 1);

    PQRegistryDiskSnapshot persisted;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        block.GetHash(), persisted));
    BOOST_CHECK_THROW(
        manager.SnapshotDatabase().WriteThrough(
            block.GetHash(), persisted, /*fSync=*/true),
        dbwrapper_error);

    manager.SnapshotDatabase().FailNextFlushBatchForTesting();
    BOOST_REQUIRE(manager.Flush(/*fSync=*/false));
    BOOST_CHECK_THROW((void)manager.Flush(/*fSync=*/true), dbwrapper_error);
    BOOST_REQUIRE(manager.Flush(/*fSync=*/true));
}

BOOST_AUTO_TEST_CASE(mempool_prepass_defers_owner_and_slh_authorization)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(201)};
    const uint256 pro_tx_hash{NonNullHash(202)};
    const uint256 parent{NonNullHash(203)};
    auto key{DeterministicKey(83)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto valid{GlobalRegistration(
        genesis, pro_tx_hash, key, owner_key,
        CommitmentAt(config, 1295, 1, 201), 201)};
    const auto corrupted{CorruptAuthorization(valid)};
    PQRegistryManager manager(MemoryDB(2), genesis, config);
    PQRegistryError error;

    auto callbacks{Member(genesis, pro_tx_hash, owner_key_id)};
    const auto verify_owner{callbacks.verify_initial_owner_authorization};
    std::size_t owner_calls{0};
    callbacks.verify_initial_owner_authorization =
        [&](const GlobalKeyTxPayload& payload, const uint256& digest) {
            ++owner_calls;
            return verify_owner(payload, digest);
        };

    BOOST_REQUIRE(manager.ValidateTransaction(
        *corrupted, parent, 1295, callbacks, /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(owner_calls, 0U);
    BOOST_CHECK(!manager.ValidateTransaction(
        *corrupted, parent, 1295, callbacks, /*check_sigs=*/true, error));
    BOOST_CHECK_EQUAL(owner_calls, 1U);
    BOOST_CHECK(error.result ==
                PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);
    BOOST_CHECK(error.state_result ==
                OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);

    // SYSCOIN: Block processing is the consensus owner of tx86
    // authorization after the structural special-tx prepass. Its public API
    // must never inherit the prepass's check_sigs=false optimization.
    const auto corrupted_block{Block(
        parent, 202,
        {OrdinaryTransaction(202), corrupted})};
    BOOST_CHECK(!manager.ProcessBlock(
        corrupted_block, 1295, callbacks, /*fJustCheck=*/true, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);
    BOOST_CHECK(error.state_result ==
                OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);
    BOOST_CHECK_EQUAL(owner_calls, 2U);

    CMutableTransaction skipped_version{*valid};
    GlobalKeyTxPayload skipped_payload;
    BOOST_REQUIRE(GetTxPayload(skipped_version, skipped_payload));
    skipped_payload.candidate.key_version = 2;
    SetTxPayload(skipped_version, skipped_payload);
    BOOST_CHECK(!manager.ValidateTransaction(
        CTransaction{skipped_version}, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);
    BOOST_CHECK(error.state_result ==
                OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);

    CMutableTransaction skipped_generation{*valid};
    BOOST_REQUIRE(GetTxPayload(skipped_generation, skipped_payload));
    skipped_payload.candidate.child_key_commitment.generation = 2;
    SetTxPayload(skipped_generation, skipped_payload);
    BOOST_CHECK(!manager.ValidateTransaction(
        CTransaction{skipped_generation}, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);
    BOOST_CHECK(error.state_result ==
                OperatorKeyStateResult::GLOBAL_REGISTRATION_AUTH_FAILED);

    CMutableTransaction exhausted_generation{*valid};
    BOOST_REQUIRE(GetTxPayload(exhausted_generation, skipped_payload));
    skipped_payload.candidate.child_key_commitment.generation =
        CHILD_KEY_TREE_MAX_GENERATION + 1;
    BOOST_CHECK_THROW(SetTxPayload(exhausted_generation, skipped_payload),
                      std::ios_base::failure);

    BOOST_REQUIRE(manager.ValidateTransaction(
        *valid, parent, 1295, callbacks, /*check_sigs=*/true, error));
    BOOST_CHECK_EQUAL(owner_calls, 3U);
}

BOOST_AUTO_TEST_CASE(branches_preserve_exact_tree_history_and_cutoff_roots)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(11)};
    const uint256 pro_tx_hash{NonNullHash(12)};
    auto key{DeterministicKey(7)};
    auto key_a{DeterministicKey(8)};
    auto key_b{DeterministicKey(9)};
    auto key_c{DeterministicKey(10)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    PQRegistryManager manager(MemoryDB(3), genesis, config);
    PQRegistryError error;
    const auto old_commitment{CommitmentAt(config, 1295, 1, 11)};
    const auto registration{Block(
        NonNullHash(13), 10,
        {OrdinaryTransaction(10),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            old_commitment, 11)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        false, error));
    PQRegistrySnapshot registered;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        registered, error));
    const GlobalKeyRecord current{OnlyOperator(registered).global_key};

    const auto commitment_a{CommitmentAt(config, 1296, 2, 12)};
    const auto commitment_b{CommitmentAt(config, 1296, 2, 13)};
    const auto branch_a{Block(
        registration.GetHash(), 20,
        {OrdinaryTransaction(20),
         GlobalRotation(genesis, pro_tx_hash, current, key, key_a,
                        commitment_a, 21)})};
    const auto branch_b{Block(
        registration.GetHash(), 30,
        {OrdinaryTransaction(30),
         GlobalRotation(genesis, pro_tx_hash, current, key, key_b,
                        commitment_b, 31)})};
    const auto key_only_branch{Block(
        registration.GetHash(), 40,
        {OrdinaryTransaction(40),
         GlobalRotation(genesis, pro_tx_hash, current, key, key_c,
                        old_commitment, 41)})};
    const auto callbacks{Member(genesis, pro_tx_hash, owner_key_id)};
    BOOST_REQUIRE(manager.ProcessBlock(branch_a, 1296, callbacks, false,
                                       error));
    BOOST_REQUIRE(manager.ProcessBlock(branch_b, 1296, callbacks, false,
                                       error));
    BOOST_REQUIRE(manager.ProcessBlock(key_only_branch, 1296, callbacks,
                                       false, error));

    PQRegistrySnapshot a;
    PQRegistrySnapshot b;
    PQRegistrySnapshot key_only;
    BOOST_REQUIRE(manager.GetSnapshot(
        branch_a.GetHash(), registration.GetHash(), 1296, a, error));
    BOOST_REQUIRE(manager.GetSnapshot(
        branch_b.GetHash(), registration.GetHash(), 1296, b, error));
    BOOST_REQUIRE(manager.GetSnapshot(
        key_only_branch.GetHash(), registration.GetHash(), 1296, key_only,
        error));
    BOOST_CHECK(a.consensus_state_root != b.consensus_state_root);
    BOOST_CHECK(a.HasUsedTreeId(old_commitment.tree_id));
    BOOST_CHECK(a.HasUsedTreeId(commitment_a.tree_id));
    BOOST_CHECK(!a.HasUsedTreeId(commitment_b.tree_id));
    BOOST_CHECK(b.HasUsedTreeId(old_commitment.tree_id));
    BOOST_CHECK(b.HasUsedTreeId(commitment_b.tree_id));
    BOOST_CHECK(!b.HasUsedTreeId(commitment_a.tree_id));
    BOOST_CHECK_EQUAL(key_only.used_tree_ids.size(), 1U);
    BOOST_CHECK(key_only.block_tree_ids.empty());

    const auto& state_a{OnlyOperator(a)};
    const auto frozen{state_a.ResolveChildRoot(0)};
    const auto future{state_a.ResolveChildRoot(1)};
    BOOST_REQUIRE(frozen.record);
    BOOST_REQUIRE(future.record);
    BOOST_CHECK(frozen.status ==
                ChildRootResolutionStatus::FROZEN_PRESENT);
    BOOST_CHECK(frozen.record->commitment == old_commitment);
    BOOST_CHECK(future.status ==
                ChildRootResolutionStatus::MUTABLE_PRESENT);
    BOOST_CHECK(future.record->commitment == commitment_a);

    PQRegistrySnapshot undone;
    BOOST_REQUIRE(manager.UndoBlock(
        branch_a.GetHash(), 1296, undone, error));
    BOOST_CHECK(undone.block_hash == registration.GetHash());
    BOOST_REQUIRE_EQUAL(undone.used_tree_ids.size(), 1U);
    BOOST_CHECK(undone.used_tree_ids.front() == old_commitment.tree_id);
}

BOOST_AUTO_TEST_CASE(payment_eligibility_reuses_unchanged_registry_state)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(161)};
    const uint256 pro_tx_hash{NonNullHash(162)};
    auto key{DeterministicKey(84)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto callbacks{Member(genesis, pro_tx_hash, owner_key_id)};
    const auto registration{Block(
        NonNullHash(163), 164,
        {OrdinaryTransaction(164),
         GlobalRegistration(
             genesis, pro_tx_hash, key, owner_key,
             CommitmentAt(config, 1295, 1, 165), 165)})};
    const auto cutoff{Block(
        registration.GetHash(), 166, {OrdinaryTransaction(166)})};
    const auto steady{Block(
        cutoff.GetHash(), 167, {OrdinaryTransaction(167)})};

    PQRegistryManager manager(MemoryDB(161), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, callbacks, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(cutoff, 1296, callbacks, false,
                                       error));
    BOOST_REQUIRE(manager.ProcessBlock(steady, 1297, callbacks, false,
                                       error));

    PQPaymentEligibleProTxHashesPtr first;
    PQPaymentEligibleProTxHashesPtr repeated;
    PQPaymentEligibleProTxHashesPtr next_block;
    BOOST_REQUIRE(manager.GetPaymentEligibleProTxHashes(
        cutoff.GetHash(), registration.GetHash(), 1296, 0, first, error));
    BOOST_REQUIRE(manager.GetPaymentEligibleProTxHashes(
        cutoff.GetHash(), registration.GetHash(), 1296, 0, repeated,
        error));
    BOOST_REQUIRE(manager.GetPaymentEligibleProTxHashes(
        steady.GetHash(), cutoff.GetHash(), 1297, 0, next_block, error));
    BOOST_REQUIRE(first);
    BOOST_CHECK(std::binary_search(first->begin(), first->end(),
                                   pro_tx_hash));
    BOOST_CHECK(first == repeated);
    // SYSCOIN: The block hash changes, but an unchanged registry root and
    // payment epoch must retain the same derived admission view.
    BOOST_CHECK(first == next_block);

    PQRegistryReadView cutoff_view;
    PQRegistryReadView steady_view;
    BOOST_REQUIRE(manager.GetReadView(
        cutoff.GetHash(), registration.GetHash(), 1296, cutoff_view,
        error));
    BOOST_REQUIRE(manager.GetReadView(
        steady.GetHash(), cutoff.GetHash(), 1297, steady_view, error));
    BOOST_CHECK(cutoff_view.SharesStateWith(steady_view));
    BOOST_CHECK_EQUAL(cutoff_view.OperatorCount(), 1U);

    PQPaymentEligibleProTxHashesPtr next_epoch;
    BOOST_REQUIRE(manager.GetPaymentEligibleProTxHashes(
        steady.GetHash(), cutoff.GetHash(), 1297, 1, next_epoch, error));
    BOOST_REQUIRE(next_epoch);
    BOOST_CHECK(next_epoch != first);
}

BOOST_AUTO_TEST_CASE(removal_drops_operator_but_retains_tree_id)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(21)};
    const uint256 pro_tx_hash{NonNullHash(22)};
    auto key{DeterministicKey(19)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto commitment{CommitmentAt(config, 1295, 1, 21)};
    PQRegistryManager manager(MemoryDB(4), genesis, config);
    PQRegistryError error;
    const auto registration{Block(
        NonNullHash(23), 40,
        {OrdinaryTransaction(40),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 41)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        false, error));
    const auto removed{Block(registration.GetHash(), 42,
                             {OrdinaryTransaction(42)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        removed, 1296,
        Member(genesis, pro_tx_hash, owner_key_id,
               /*exists_after=*/false),
        false, error));

    PQRegistryReadView registered_view;
    PQRegistryReadView removed_view;
    BOOST_REQUIRE(manager.GetReadView(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        registered_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        removed.GetHash(), registration.GetHash(), 1296, removed_view,
        error));
    BOOST_CHECK(!registered_view.SharesStateWith(removed_view));
    BOOST_CHECK(registered_view.SharesTreeHistoryWith(removed_view));

    PQRegistryDiskSnapshot delta;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        removed.GetHash(), delta));
    BOOST_CHECK_EQUAL(delta.is_checkpoint, 0U);
    BOOST_REQUIRE_EQUAL(delta.removed_operators.size(), 1U);
    BOOST_CHECK(delta.removed_operators.front() == pro_tx_hash);

    PQRegistrySnapshot snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        removed.GetHash(), registration.GetHash(), 1296, snapshot, error));
    BOOST_CHECK(snapshot.operator_states.empty());
    BOOST_REQUIRE_EQUAL(snapshot.used_tree_ids.size(), 1U);
    BOOST_CHECK(snapshot.used_tree_ids.front() == commitment.tree_id);
}

BOOST_AUTO_TEST_CASE(revocation_requires_delayed_fresh_owner_recovery)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(111)};
    const uint256 pro_tx_hash{NonNullHash(112)};
    auto key{DeterministicKey(69)};
    auto recovery_key{DeterministicKey(117)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto first_tree{CommitmentAt(config, 1295, 1, 111)};
    PQRegistryManager manager(MemoryDB(5), genesis, config);
    PQRegistryError error;
    const auto registration{Block(
        NonNullHash(113), 110,
        {OrdinaryTransaction(110),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            first_tree, 111)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        false, error));
    PQRegistrySnapshot registered;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        registered, error));
    const GlobalKeyRecord current{OnlyOperator(registered).global_key};
    const auto revoke{Block(
        registration.GetHash(), 112,
        {OrdinaryTransaction(112),
         ProviderRevocation(genesis, pro_tx_hash, current, key, 113)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        revoke, 1296, Member(genesis, pro_tx_hash, owner_key_id), false,
        error));

    PQRegistrySnapshot historical;
    PQRegistrySnapshot revoked;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        historical, error));
    BOOST_REQUIRE(manager.GetSnapshot(
        revoke.GetHash(), registration.GetHash(), 1296, revoked, error));
    BOOST_CHECK(OnlyOperator(historical).HasActiveGlobalKey());
    BOOST_CHECK(!OnlyOperator(revoked).HasActiveGlobalKey());
    BOOST_CHECK(OnlyOperator(revoked).frozen_child_roots.empty());
    BOOST_CHECK(revoked.HasUsedTreeId(first_tree.tree_id));

    PQRegistryReadView historical_view;
    PQRegistryReadView revoked_view;
    BOOST_REQUIRE(manager.GetReadView(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        historical_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        revoke.GetHash(), registration.GetHash(), 1296, revoked_view,
        error));
    const auto active_owner{historical_view.FindActiveOperatorByGlobalKey(
        OnlyOperator(historical).global_key.public_key)};
    BOOST_REQUIRE(active_owner);
    BOOST_CHECK(*active_owner == pro_tx_hash);
    BOOST_CHECK(!revoked_view.FindActiveOperatorByGlobalKey(
        OnlyOperator(revoked).global_key.public_key));

    const auto recovery_tree{CommitmentAt(config, 1297, 2, 112)};
    const auto recovery{Block(
        revoke.GetHash(), 114,
        {OrdinaryTransaction(114),
         GlobalRecovery(genesis, pro_tx_hash,
                        OnlyOperator(revoked).global_key, recovery_key,
                        owner_key, recovery_tree, 115)})};
    BOOST_CHECK(!manager.ProcessBlock(
        recovery, 1297, Member(genesis, pro_tx_hash, owner_key_id), true,
        error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);
    BOOST_CHECK(error.state_result ==
                OperatorKeyStateResult::GLOBAL_RECOVERY_NOT_ALLOWED);
}

BOOST_AUTO_TEST_CASE(restart_reconstructs_frozen_root_and_tree_history)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(71)};
    const uint256 pro_tx_hash{NonNullHash(72)};
    auto key{DeterministicKey(37)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto commitment{CommitmentAt(config, 1295, 1, 71)};
    auto db{MemoryDB(6)};
    db.path = m_path_root / "pq_registry_root_restart";
    db.memory_only = false;
    uint256 registration_hash;
    uint256 cutoff_hash;

    {
        PQRegistryManager manager(db, genesis, config);
        PQRegistryError error;
        const auto registration{Block(
            NonNullHash(73), 70,
            {OrdinaryTransaction(70),
             GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                                commitment, 71)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            registration, 1295,
            Member(genesis, pro_tx_hash, owner_key_id), false, error));
        registration_hash = registration.GetHash();
        const auto cutoff{Block(registration_hash, 72,
                                {OrdinaryTransaction(72)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            cutoff, 1296, Member(genesis, pro_tx_hash, owner_key_id), false,
            error));
        cutoff_hash = cutoff.GetHash();
        BOOST_REQUIRE(manager.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    PQRegistryManager restarted(db, genesis, config);
    PQRegistryError error;
    PQRegistrySnapshot snapshot;
    BOOST_REQUIRE(restarted.GetSnapshot(
        cutoff_hash, registration_hash, 1296, snapshot, error));
    BOOST_CHECK(snapshot.HasUsedTreeId(commitment.tree_id));
    const auto frozen{OnlyOperator(snapshot).ResolveChildRoot(0)};
    BOOST_REQUIRE(frozen.record);
    BOOST_CHECK(frozen.status ==
                ChildRootResolutionStatus::FROZEN_PRESENT);
    BOOST_CHECK(frozen.record->commitment == commitment);
    BOOST_CHECK(snapshot.RecomputeConsensusStateRoot(genesis) ==
                snapshot.consensus_state_root);
}

BOOST_AUTO_TEST_CASE(reconstruction_rejects_broken_root_link)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(101)};
    const uint256 pro_tx_hash{NonNullHash(102)};
    auto key{DeterministicKey(61)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    PQRegistryManager manager(MemoryDB(7), genesis, config);
    PQRegistryError error;
    const auto registration{Block(
        NonNullHash(103), 100,
        {OrdinaryTransaction(100),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            CommitmentAt(config, 1295, 1, 101), 101)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id),
        false, error));
    const auto child{Block(registration.GetHash(), 102,
                           {OrdinaryTransaction(102)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        child, 1296, Member(genesis, pro_tx_hash, owner_key_id), false,
        error));

    PQRegistryDiskSnapshot corrupt;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        child.GetHash(), corrupt));
    corrupt.previous_consensus_state_root = NonNullHash(104);
    BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
        child.GetHash(), corrupt, /*fSync=*/true));
    BOOST_REQUIRE(manager.PruneSnapshot(child.GetHash()));

    PQRegistrySnapshot rejected;
    BOOST_CHECK(!manager.GetSnapshot(
        child.GetHash(), registration.GetHash(), 1296, rejected, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);
}

BOOST_AUTO_TEST_CASE(rejects_early_noncanonical_mismatched_and_duplicate_updates)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(31)};
    const uint256 pro_tx_hash{NonNullHash(32)};
    auto key{DeterministicKey(29)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto commitment{CommitmentAt(config, 1295, 1, 31)};
    PQRegistryManager manager(MemoryDB(8), genesis, config);
    PQRegistryError error;

    const auto early{Block(
        NonNullHash(33), 50,
        {OrdinaryTransaction(50),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 51)})};
    BOOST_CHECK(!manager.ProcessBlock(
        early, 1294, Member(genesis, pro_tx_hash, owner_key_id), false,
        error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::PQ_TX_BEFORE_PREPARATION);

    CMutableTransaction noncanonical{
        *GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 52)};
    const int payload_output{GetSyscoinDataOutput(noncanonical)};
    BOOST_REQUIRE(payload_output >= 0);
    noncanonical.vout[payload_output].scriptPubKey << OP_TRUE;
    const auto noncanonical_block{Block(
        NonNullHash(34), 52,
        {OrdinaryTransaction(52),
         MakeTransactionRef(std::move(noncanonical))})};
    BOOST_CHECK(!manager.ProcessBlock(
        noncanonical_block, 1295,
        Member(genesis, pro_tx_hash, owner_key_id), false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD);

    CMutableTransaction changed{
        *GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 53)};
    changed.vin[0].prevout = COutPoint{NonNullHash(99), 99};
    const auto mismatch{Block(
        NonNullHash(35), 53,
        {OrdinaryTransaction(53), MakeTransactionRef(std::move(changed))})};
    BOOST_CHECK(!manager.ProcessBlock(
        mismatch, 1295, Member(genesis, pro_tx_hash, owner_key_id), false,
        error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::TRANSACTION_INPUTS_HASH_MISMATCH);

    const auto denied{Block(
        NonNullHash(36), 54,
        {OrdinaryTransaction(54),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 55)})};
    BOOST_CHECK(!manager.ProcessBlock(
        denied, 1295,
        Member(genesis, pro_tx_hash, owner_key_id, true,
               /*owner_authorized=*/false),
        false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::OWNER_AUTHORIZATION_FAILED);

    const auto duplicate{Block(
        NonNullHash(37), 56,
        {OrdinaryTransaction(56),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 57),
         GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            commitment, 58)})};
    BOOST_CHECK(!manager.ProcessBlock(
        duplicate, 1295, Member(genesis, pro_tx_hash, owner_key_id), false,
        error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::DUPLICATE_OPERATOR_UPDATE);
}

BOOST_AUTO_TEST_CASE(global_keys_and_tree_ids_are_unique)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(81)};
    const uint256 first{NonNullHash(82)};
    const uint256 second{NonNullHash(83)};
    auto key{DeterministicKey(47)};
    auto other_key{DeterministicKey(48)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto first_tree{CommitmentAt(config, 1295, 1, 81)};
    const auto second_tree{CommitmentAt(config, 1295, 1, 82)};
    const auto callbacks{Members(genesis, {first, second}, {first, second},
                                 owner_key_id)};

    PQRegistryManager duplicate_key_manager(MemoryDB(9), genesis, config);
    PQRegistryError error;
    const auto duplicate_key_block{Block(
        NonNullHash(84), 80,
        {OrdinaryTransaction(80),
         GlobalRegistration(genesis, first, key, owner_key, first_tree, 81),
         GlobalRegistration(genesis, second, key, owner_key, second_tree,
                            82)})};
    BOOST_CHECK(!duplicate_key_manager.ProcessBlock(
        duplicate_key_block, 1295, callbacks, false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK(error.pro_tx_hash == second);

    PQRegistryManager duplicate_tree_manager(MemoryDB(10), genesis, config);
    auto reused_tree{first_tree};
    reused_tree.root = NonNullHash(99'999);
    const auto duplicate_tree_block{Block(
        NonNullHash(85), 83,
        {OrdinaryTransaction(83),
         GlobalRegistration(genesis, first, key, owner_key, first_tree, 84),
         GlobalRegistration(genesis, second, other_key, owner_key,
                            reused_tree, 85)})};
    BOOST_CHECK(!duplicate_tree_manager.ProcessBlock(
        duplicate_tree_block, 1295, callbacks, false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::DUPLICATE_CHILD_TREE_ID);
    BOOST_CHECK(error.pro_tx_hash == second);
}

BOOST_AUTO_TEST_SUITE_END()
