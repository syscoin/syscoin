// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/pq_registry.h>

#include <consensus/params.h>
#include <crypto/slhdsa/slhdsa.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <hash.h>
#include <key.h>
#include <llmq/pq_global_auth.h>
#include <messagesigner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace llmq::pq;

namespace llmq::pq::test {

struct PQRegistryReconstructionStats {
    uint64_t authenticated_records{0};
    uint64_t reused_records{0};
    uint64_t tree_id_hashes{0};
    uint64_t state_hashes{0};
    std::size_t cached_views{0};
    std::size_t cached_payment_views{0};
    uint64_t gc_floor_revision{0};
};

class PQRegistryManagerTestAccess {
public:
    static PQRegistryReconstructionStats Stats(
        const PQRegistryManager& manager)
    {
        LOCK(manager.m_mutex);
        return {manager.m_reconstruction_authenticated_records,
                manager.m_reconstruction_reused_records,
                manager.m_reconstruction_tree_id_hashes,
                manager.m_reconstruction_state_hashes,
                manager.m_snapshot_cache.size(),
                manager.m_payment_eligibility_cache.size(),
                manager.m_gc_floor_revision};
    }

    static void ResetReconstructionStats(
        const PQRegistryManager& manager)
    {
        LOCK(manager.m_mutex);
        manager.m_reconstruction_authenticated_records = 0;
        manager.m_reconstruction_reused_records = 0;
        manager.m_reconstruction_tree_id_hashes = 0;
        manager.m_reconstruction_state_hashes = 0;
    }

    static void DropAllCaches(PQRegistryManager& manager)
    {
        LOCK(manager.m_mutex);
        manager.m_snapshot_cache.clear();
        manager.m_snapshot_cache_index.clear();
        manager.m_payment_eligibility_cache.clear();
        manager.m_payment_eligibility_cache_index.clear();
        manager.m_snapshot_db->SetReadCacheSize(0);
        manager.m_snapshot_db->SetReadCacheSize(
            PQ_REGISTRY_SNAPSHOT_CACHE_SIZE);
    }

    static void DropCachedSnapshot(
        PQRegistryManager& manager,
        const uint256& block_hash)
    {
        LOCK(manager.m_mutex);
        const auto cached{
            manager.m_snapshot_cache_index.find(block_hash)};
        if (cached == manager.m_snapshot_cache_index.end()) return;
        manager.m_snapshot_cache.erase(cached->second);
        manager.m_snapshot_cache_index.erase(cached);
    }

    static bool ReadExactDiskSnapshot(
        PQRegistryManager& manager,
        const uint256& block_hash,
        PQRegistryDiskSnapshot& snapshot)
    {
        LOCK(manager.m_mutex);
        using ExactReadResult = typename CEvoDB<
            uint256, PQRegistryDiskSnapshot,
            StaticSaltedHasher>::ExactDiskReadResult;
        return manager.m_snapshot_db->ReadExactDiskForGC(
                   block_hash, snapshot) == ExactReadResult::FOUND;
    }

    static bool EraseExactDiskSnapshot(
        PQRegistryManager& manager,
        const uint256& block_hash)
    {
        LOCK(manager.m_mutex);
        const std::array<uint256, 1> keys{block_hash};
        return manager.m_snapshot_db->EraseExactDiskKeysForGC(
            keys, /*fSync=*/true);
    }

    static bool EraseExactDiskSnapshots(
        PQRegistryManager& manager,
        std::span<const uint256> block_hashes)
    {
        LOCK(manager.m_mutex);
        return manager.m_snapshot_db->EraseExactDiskKeysForGC(
            block_hashes, /*fSync=*/true);
    }

    static bool AppendTrailingDiskByte(
        PQRegistryManager& manager,
        const uint256& block_hash)
    {
        LOCK(manager.m_mutex);
        return manager.m_snapshot_db->AppendTrailingValueByteForTesting(
            block_hash);
    }

    static bool RewriteExactDiskSnapshot(
        PQRegistryManager& manager,
        const uint256& block_hash,
        const PQRegistryDiskSnapshot& snapshot)
    {
        LOCK(manager.m_mutex);
        const auto cached{manager.m_snapshot_cache_index.find(block_hash)};
        if (cached != manager.m_snapshot_cache_index.end()) {
            manager.m_snapshot_cache.erase(cached->second);
            manager.m_snapshot_cache_index.erase(cached);
        }
        return manager.m_snapshot_db->WriteThrough(
            block_hash, snapshot, /*fSync=*/true);
    }
};

} // namespace llmq::pq::test

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

const OperatorKeyState& RequiredOperator(const PQRegistrySnapshot& snapshot,
                                         const uint256& pro_tx_hash)
{
    const auto* state{snapshot.FindOperator(pro_tx_hash)};
    BOOST_REQUIRE(state != nullptr);
    return *state;
}

evo::AuxiliaryHistoryGCAuthorization FloorAuthorization(int32_t height,
                                                        uint32_t tag)
{
    return {
        evo::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {height, NonNullHash(tag)},
    };
}

evo::AuxiliaryHistoryGCComponent FloorComponent(
    const evo::PQRegistryGCClosure& closure)
{
    const auto encoded{evo::EncodePQRegistryGCClosure(closure)};
    BOOST_REQUIRE(encoded);
    evo::AuxiliaryHistoryGCComponent component{
        evo::PQRegistryGCClosure::VERSION,
        closure.generation,
        *encoded,
    };
    BOOST_REQUIRE(component.IsValid());
    return component;
}

struct EmptyRootedGCHistory {
    PQRegistryConfig config{FastConfig()};
    uint256 genesis;
    uint256 configuration_id;
    int32_t island_base_height;
    int32_t anchor_height;
    int32_t initial_checkpoint_height;
    int32_t second_checkpoint_height;
    std::vector<CBlock> blocks;
    std::vector<evo::AuxiliaryHistoryGCBlockIdentity> identities;
    std::unique_ptr<PQRegistryManager> manager;

    explicit EmptyRootedGCHistory(uint32_t id, int32_t anchor_offset = 7)
        : genesis{NonNullHash(id)},
          configuration_id{NonNullHash(id + 1)},
          island_base_height{
              config.preparation_height +
              anchor_offset / PQ_REGISTRY_CHECKPOINT_INTERVAL *
                  PQ_REGISTRY_CHECKPOINT_INTERVAL},
          anchor_height{config.preparation_height + anchor_offset},
          initial_checkpoint_height{
              island_base_height + PQ_REGISTRY_CHECKPOINT_INTERVAL},
          second_checkpoint_height{
              initial_checkpoint_height + PQ_REGISTRY_CHECKPOINT_INTERVAL}
    {
        BOOST_REQUIRE_GE(anchor_offset, 0);
        uint32_t block_id{id + 10'000};
        uint256 previous{NonNullHash(block_id++)};
        blocks.reserve(static_cast<std::size_t>(
            second_checkpoint_height - config.preparation_height + 1));
        identities.reserve(blocks.capacity());
        for (int32_t height{config.preparation_height};
             height <= second_checkpoint_height; ++height) {
            blocks.push_back(Block(
                previous, block_id,
                {OrdinaryTransaction(block_id)}));
            previous = blocks.back().GetHash();
            identities.push_back({height, previous});
            ++block_id;
        }
        PQRegistrySnapshot empty;
        const auto empty_root{empty.RecomputeConsensusStateRoot(genesis)};
        BOOST_REQUIRE(empty_root);
        const auto& anchor{Identity(anchor_height)};
        manager = std::make_unique<PQRegistryManager>(
            MemoryDB(id), genesis, config,
            PQRegistryGCRootConfig{
                configuration_id, anchor, *empty_root});
        PQRegistryError error;
        for (std::size_t i{0}; i < blocks.size(); ++i) {
            BOOST_REQUIRE(manager->ProcessBlock(
                blocks[i], identities[i].height,
                Members(genesis, {}, {}, CKeyID{}), {},
                /*fJustCheck=*/false, error));
        }
    }

    const evo::AuxiliaryHistoryGCBlockIdentity& Identity(
        int32_t height) const
    {
        BOOST_REQUIRE_GE(height, config.preparation_height);
        BOOST_REQUIRE_LE(height, second_checkpoint_height);
        return identities[static_cast<std::size_t>(
            height - config.preparation_height)];
    }

    PQRegistryGCAuthenticationContext Context(int32_t target) const
    {
        PQRegistryGCAuthenticationContext context;
        const auto first{identities.begin()};
        context.legacy_island.assign(
            first + (island_base_height - config.preparation_height),
            first + (anchor_height - config.preparation_height + 1));
        const int32_t segment_base{target == initial_checkpoint_height
            ? anchor_height
            : target - PQ_REGISTRY_CHECKPOINT_INTERVAL};
        context.rooted_segment.assign(
            first + (segment_base - config.preparation_height),
            first + (target - config.preparation_height + 1));
        BOOST_REQUIRE(context.IsStructurallyValid());
        return context;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_registry_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_registry_consensus_root_is_frozen)
{
    PQRegistrySnapshot empty;
    const auto root{empty.RecomputeConsensusStateRoot(NonNullHash(3))};
    BOOST_REQUIRE(root);
    BOOST_CHECK(*root == uint256S(
        "30baf90ece972a64ce79c3661c960928329f13f802a66a7e2fb906eb8b2e5728"));
}

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
        preparation, config.preparation_height, callbacks, {}, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        cutoff, config.preparation_height + 1, callbacks, {}, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        steady_a, config.preparation_height + 2, callbacks, {}, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(
        steady_b, config.preparation_height + 2, callbacks, {}, false, error));

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
    const auto retained_operators{cutoff_view.ShareOperatorStates()};
    BOOST_REQUIRE(retained_operators);
    BOOST_CHECK(retained_operators == steady_a_view.ShareOperatorStates());
    BOOST_CHECK(retained_operators == steady_b_view.ShareOperatorStates());
    BOOST_CHECK(steady_a_view.BlockHash() != steady_b_view.BlockHash());
    BOOST_CHECK(steady_a_view.PreviousBlockHash() == cutoff.GetHash());
    BOOST_CHECK(steady_b_view.PreviousBlockHash() == cutoff.GetHash());
    BOOST_CHECK(steady_a_view.ConsensusStateRoot() ==
                steady_b_view.ConsensusStateRoot());
    const std::size_t retained_operator_count{cutoff_view.OperatorCount()};
    cutoff_view = {};
    steady_a_view = {};
    steady_b_view = {};

    PQRegistryReadView previous_historical;
    for (int32_t height{1};
         height <= static_cast<int32_t>(PQ_REGISTRY_SNAPSHOT_CACHE_SIZE + 1);
         ++height) {
        PQRegistryReadView historical;
        BOOST_REQUIRE(manager.GetReadView(
            NonNullHash(400 + height), NonNullHash(399 + height), height,
            historical, error));
        if (previous_historical.IsValid()) {
            BOOST_CHECK(previous_historical.SharesStateWith(historical));
        }
        previous_historical = std::move(historical);
    }
    BOOST_CHECK(genesis_view.IsValid());
    BOOST_CHECK(genesis_view.BlockHash() == genesis_block);
    // Evicting snapshot views cannot invalidate a quorum-owned operator view.
    BOOST_CHECK_EQUAL(retained_operators->size(), retained_operator_count);
}

BOOST_AUTO_TEST_CASE(preparation_token_before_registry_activation_never_persists)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(191)};
    const auto block{Block(
        NonNullHash(192), 193, {OrdinaryTransaction(193)})};
    PQRegistryManager manager(MemoryDB(191), genesis, config);
    PQRegistryError error;
    PQRegistryPreparedBlock prepared;

    BOOST_REQUIRE(manager.PrepareBlock(
        block, config.preparation_height - 1, {}, {}, prepared, error));
    BOOST_CHECK(prepared.IsValid());
    BOOST_CHECK(!prepared.ConsensusStateRoot().IsNull());
    BOOST_CHECK_EQUAL(manager.SnapshotDatabase().CountPersistedEntries(), 0);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(block.GetHash()));

    BOOST_REQUIRE(manager.CommitPreparedBlock(prepared, error));
    BOOST_CHECK(!prepared.IsValid());
    BOOST_CHECK(prepared.ConsensusStateRoot().IsNull());
    BOOST_CHECK_EQUAL(manager.SnapshotDatabase().CountPersistedEntries(), 0);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(block.GetHash()));
}

BOOST_AUTO_TEST_CASE(initial_root_registration_prepares_purely_and_commits_exactly)
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
    const auto callbacks{Member(genesis, pro_tx_hash, owner_key_id)};
    BOOST_REQUIRE(manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/true, error));

    PQRegistryPreparedBlock prepared;
    BOOST_REQUIRE(manager.PrepareBlock(
        block, 1295, callbacks, {}, prepared, error));
    BOOST_CHECK(prepared.IsValid());
    const uint256 prepared_root{prepared.ConsensusStateRoot()};
    BOOST_CHECK(!prepared_root.IsNull());
    BOOST_CHECK_EQUAL(manager.SnapshotDatabase().CountPersistedEntries(), 0);
    PQRegistrySnapshot missing;
    BOOST_CHECK(!manager.GetSnapshot(
        block.GetHash(), parent, 1295, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    manager.SnapshotDatabase().FailNextWriteThroughForTesting();
    BOOST_CHECK_THROW((void)manager.CommitPreparedBlock(prepared, error),
                      dbwrapper_error);
    BOOST_CHECK(prepared.IsValid());
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(block.GetHash()));
    BOOST_CHECK(!manager.GetSnapshot(
        block.GetHash(), parent, 1295, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    // The failed commit has materialized the exact non-empty checkpoint in
    // the token. Moving it must retain that disk payload for the retry.
    PQRegistryPreparedBlock moved{std::move(prepared)};
    BOOST_CHECK(!prepared.IsValid());
    BOOST_CHECK(!manager.CommitPreparedBlock(prepared, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);
    BOOST_CHECK(moved.IsValid());
    BOOST_REQUIRE(manager.CommitPreparedBlock(moved, error));
    BOOST_CHECK(!moved.IsValid());
    BOOST_CHECK(!manager.CommitPreparedBlock(moved, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);

    PQRegistrySnapshot snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        block.GetHash(), parent, 1295, snapshot, error));
    BOOST_CHECK(snapshot.consensus_state_root == prepared_root);
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

    PQRegistryDiskSnapshot first_disk;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        block.GetHash(), first_disk));
    BOOST_CHECK_EQUAL(first_disk.is_checkpoint, 1U);
    BOOST_CHECK(first_disk.operator_states == snapshot.operator_states);
    BOOST_CHECK(first_disk.checkpoint_operator_states ==
                snapshot.operator_states);
    BOOST_CHECK(first_disk.tree_ids == snapshot.used_tree_ids);
    BOOST_CHECK(first_disk.block_tree_ids == snapshot.block_tree_ids);
    BOOST_CHECK(first_disk.removed_operators.empty());
    const auto empty_root{
        PQRegistrySnapshot{}.RecomputeConsensusStateRoot(genesis)};
    BOOST_REQUIRE(empty_root);
    BOOST_CHECK(first_disk.previous_consensus_state_root == *empty_root);
    BOOST_CHECK(first_disk.consensus_state_root == prepared_root);
    const auto persisted_entries{
        manager.SnapshotDatabase().CountPersistedEntries()};
    PQRegistryPreparedBlock replay;
    BOOST_REQUIRE(manager.PrepareBlock(
        block, 1295, callbacks, {}, replay, error));
    BOOST_CHECK(replay.ConsensusStateRoot() == prepared_root);
    BOOST_REQUIRE(manager.CommitPreparedBlock(replay, error));
    BOOST_CHECK_EQUAL(manager.SnapshotDatabase().CountPersistedEntries(),
                      persisted_entries);
    PQRegistryDiskSnapshot replay_disk;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        block.GetHash(), replay_disk));
    BOOST_CHECK(replay_disk == first_disk);

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
        Members(genesis, {}, {}, CKeyID{}), {}, /*fJustCheck=*/false, error));
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

BOOST_AUTO_TEST_CASE(prepared_block_is_manager_bound)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(171)};
    const auto block{Block(
        NonNullHash(172), 173, {OrdinaryTransaction(173)})};
    const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
    PQRegistryManager first(MemoryDB(171), genesis, config);
    PQRegistryManager second(MemoryDB(172), genesis, config);
    PQRegistryError error;
    PQRegistryPreparedBlock prepared;
    BOOST_REQUIRE(first.PrepareBlock(
        block, config.preparation_height, callbacks, {}, prepared, error));
    BOOST_CHECK(prepared.IsValid());

    BOOST_CHECK(!second.CommitPreparedBlock(prepared, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);
    BOOST_CHECK(prepared.IsValid());
    PQRegistrySnapshot missing;
    BOOST_CHECK(!second.GetSnapshot(
        block.GetHash(), block.hashPrevBlock, config.preparation_height,
        missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    BOOST_REQUIRE(first.CommitPreparedBlock(prepared, error));
    BOOST_CHECK(!prepared.IsValid());
    PQRegistrySnapshot committed;
    BOOST_REQUIRE(first.GetSnapshot(
        block.GetHash(), block.hashPrevBlock, config.preparation_height,
        committed, error));
}

BOOST_AUTO_TEST_CASE(prepared_block_rejects_recreated_manager_incarnation)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(174)};
    const auto block{Block(
        NonNullHash(175), 176, {OrdinaryTransaction(176)})};
    const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
    std::optional<PQRegistryManager> manager;
    manager.emplace(MemoryDB(174), genesis, config);
    const void* const manager_address{static_cast<const void*>(&*manager)};
    PQRegistryPreparedBlock prepared;
    PQRegistryError error;
    BOOST_REQUIRE(manager->PrepareBlock(
        block, config.preparation_height, callbacks, {}, prepared, error));

    manager.reset();
    manager.emplace(MemoryDB(175), genesis, config);
    BOOST_CHECK(static_cast<const void*>(&*manager) == manager_address);
    BOOST_CHECK(!manager->CommitPreparedBlock(prepared, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);
    BOOST_CHECK(prepared.IsValid());
}

BOOST_AUTO_TEST_CASE(prepared_write_failure_does_not_publish_and_can_retry)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(181)};
    const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
    PQRegistryManager manager(MemoryDB(181), genesis, config);
    PQRegistryError error;
    PQRegistrySnapshot missing;

    const auto preparation{Block(
        NonNullHash(182), 183, {OrdinaryTransaction(183)})};
    PQRegistryPreparedBlock prepared;
    BOOST_REQUIRE(manager.PrepareBlock(
        preparation, config.preparation_height, callbacks, {}, prepared,
        error));
    const uint256 preparation_root{prepared.ConsensusStateRoot()};
    manager.SnapshotDatabase().FailNextWriteThroughForTesting();
    BOOST_CHECK_THROW((void)manager.CommitPreparedBlock(prepared, error),
                      dbwrapper_error);
    BOOST_CHECK(prepared.IsValid());
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(
        preparation.GetHash()));
    BOOST_CHECK(!manager.GetSnapshot(
        preparation.GetHash(), preparation.hashPrevBlock,
        config.preparation_height, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);
    PQRegistryPreparedBlock moved{std::move(prepared)};
    BOOST_CHECK(!prepared.IsValid());
    BOOST_CHECK(moved.IsValid());
    BOOST_CHECK(moved.ConsensusStateRoot() == preparation_root);
    BOOST_REQUIRE(manager.CommitPreparedBlock(moved, error));
    BOOST_CHECK(!moved.IsValid());
    PQRegistryReadView preparation_view;
    BOOST_REQUIRE(manager.GetReadView(
        preparation.GetHash(), preparation.hashPrevBlock,
        config.preparation_height, preparation_view, error));
    PQRegistryDiskSnapshot preparation_disk;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        preparation.GetHash(), preparation_disk));
    BOOST_CHECK(preparation_view.ConsensusStateRoot() == preparation_root);
    BOOST_CHECK(preparation_disk.consensus_state_root == preparation_root);

    const auto cutoff{Block(
        preparation.GetHash(), 184, {OrdinaryTransaction(184)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        cutoff, config.preparation_height + 1, callbacks, {}, false,
        error));
    const auto steady{Block(
        cutoff.GetHash(), 185, {OrdinaryTransaction(185)})};
    PQRegistryPreparedBlock unchanged;
    BOOST_REQUIRE(manager.PrepareBlock(
        steady, config.preparation_height + 2, callbacks, {}, unchanged,
        error));
    manager.SnapshotDatabase().FailNextWriteThroughForTesting();
    BOOST_CHECK_THROW((void)manager.CommitPreparedBlock(unchanged, error),
                      dbwrapper_error);
    BOOST_CHECK(unchanged.IsValid());
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(steady.GetHash()));
    BOOST_CHECK(!manager.GetSnapshot(
        steady.GetHash(), steady.hashPrevBlock,
        config.preparation_height + 2, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);
    BOOST_REQUIRE(manager.CommitPreparedBlock(unchanged, error));
    BOOST_CHECK(!unchanged.IsValid());

    PQRegistryReadView cutoff_view;
    PQRegistryReadView steady_view;
    BOOST_REQUIRE(manager.GetReadView(
        cutoff.GetHash(), preparation.GetHash(),
        config.preparation_height + 1, cutoff_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        steady.GetHash(), cutoff.GetHash(),
        config.preparation_height + 2, steady_view, error));
    BOOST_CHECK(cutoff_view.SharesStateWith(steady_view));
    BOOST_CHECK(cutoff_view.SharesTreeHistoryWith(steady_view));
    BOOST_CHECK(cutoff_view.ConsensusStateRoot() ==
                steady_view.ConsensusStateRoot());
    PQRegistryDiskSnapshot steady_disk;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        steady.GetHash(), steady_disk));
    BOOST_CHECK_EQUAL(steady_disk.is_checkpoint, 0U);
    BOOST_CHECK(steady_disk.operator_states.empty());
    BOOST_CHECK(steady_disk.removed_operators.empty());
    BOOST_CHECK(steady_disk.tree_ids.empty());
    BOOST_CHECK(steady_disk.block_tree_ids.empty());
    BOOST_CHECK(steady_disk.previous_consensus_state_root ==
                cutoff_view.ConsensusStateRoot());
    BOOST_CHECK(steady_disk.consensus_state_root ==
                steady_view.ConsensusStateRoot());
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
        corrupted_block, 1295, callbacks, {}, /*fJustCheck=*/true, error));
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
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id), {},
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
    BOOST_REQUIRE(manager.ProcessBlock(branch_a, 1296, callbacks, {}, false,
                                       error));
    BOOST_REQUIRE(manager.ProcessBlock(branch_b, 1296, callbacks, {}, false,
                                       error));
    BOOST_REQUIRE(manager.ProcessBlock(key_only_branch, 1296, callbacks, {},
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

    PQRegistryReadView registered_view;
    PQRegistryReadView a_view;
    PQRegistryReadView b_view;
    PQRegistryReadView key_only_view;
    BOOST_REQUIRE(manager.GetReadView(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        registered_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        branch_a.GetHash(), registration.GetHash(), 1296, a_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        branch_b.GetHash(), registration.GetHash(), 1296, b_view, error));
    BOOST_REQUIRE(manager.GetReadView(
        key_only_branch.GetHash(), registration.GetHash(), 1296,
        key_only_view, error));
    BOOST_CHECK(!registered_view.SharesStateWith(key_only_view));
    BOOST_CHECK(registered_view.SharesTreeHistoryWith(key_only_view));
    BOOST_CHECK(!registered_view.SharesTreeHistoryWith(a_view));
    BOOST_CHECK(!registered_view.SharesTreeHistoryWith(b_view));
    BOOST_CHECK(!a_view.SharesTreeHistoryWith(b_view));

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

    BOOST_REQUIRE(manager.PreflightUndoBlock(
        registration.GetHash(), registration.hashPrevBlock, 1295, error));
    BOOST_REQUIRE(manager.PreflightUndoBlock(
        branch_a.GetHash(), registration.GetHash(), 1296, error));
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
        registration, 1295, callbacks, {}, false, error));
    BOOST_REQUIRE(manager.ProcessBlock(cutoff, 1296, callbacks, {}, false,
                                       error));
    uint256 checked_steady_root;
    BOOST_REQUIRE(manager.ProcessBlock(
        steady, 1297, callbacks, {}, true, error, &checked_steady_root));
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(steady.GetHash()));

    uint256 steady_root;
    BOOST_REQUIRE(manager.ProcessBlock(
        steady, 1297, callbacks, {}, false, error, &steady_root));
    BOOST_CHECK(steady_root == checked_steady_root);

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
    BOOST_CHECK(cutoff_view.SharesTreeHistoryWith(steady_view));
    BOOST_CHECK(steady_root == cutoff_view.ConsensusStateRoot());
    BOOST_CHECK_EQUAL(cutoff_view.OperatorCount(), 1U);

    PQRegistryDiskSnapshot steady_delta;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        steady.GetHash(), steady_delta));
    BOOST_CHECK_EQUAL(steady_delta.is_checkpoint, 0U);
    BOOST_CHECK(steady_delta.operator_states.empty());
    BOOST_CHECK(steady_delta.removed_operators.empty());
    BOOST_CHECK(steady_delta.tree_ids.empty());
    BOOST_CHECK(steady_delta.block_tree_ids.empty());
    BOOST_CHECK(steady_delta.consensus_state_root ==
                cutoff_view.ConsensusStateRoot());

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
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id), {},
        false, error));
    const auto removed{Block(registration.GetHash(), 42,
                             {OrdinaryTransaction(42)})};
    const std::vector<uint256> net_removed{pro_tx_hash};
    auto removal_callbacks{Member(
        genesis, pro_tx_hash, owner_key_id,
        /*exists_after=*/false)};
    std::size_t after_calls{0};
    const auto exists_after{removal_callbacks.dmn_exists_after};
    removal_callbacks.dmn_exists_after = [&](const uint256& hash) {
        ++after_calls;
        return exists_after(hash);
    };
    BOOST_REQUIRE(manager.ProcessBlock(
        removed, 1296, removal_callbacks, net_removed, false, error));
    BOOST_CHECK_EQUAL(after_calls, 0U);

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

BOOST_AUTO_TEST_CASE(removal_merge_is_exact_check_only_is_pure_and_forks_reconstruct)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(401)};
    std::vector<uint256> hashes{
        NonNullHash(402), NonNullHash(403), NonNullHash(404),
        NonNullHash(405)};
    std::sort(hashes.begin(), hashes.end());
    const uint256& first{hashes[0]};
    const uint256& middle{hashes[1]};
    const uint256& absent{hashes[2]};
    const uint256& last{hashes[3]};
    const std::vector<uint256> registered_hashes{first, middle, last};

    auto first_key{DeterministicKey(121)};
    auto middle_key{DeterministicKey(122)};
    auto last_key{DeterministicKey(123)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto registration{Block(
        NonNullHash(406), 407,
        {OrdinaryTransaction(407),
         GlobalRegistration(
             genesis, first, first_key, owner_key,
             CommitmentAt(config, 1295, 1, 401), 408),
         GlobalRegistration(
             genesis, middle, middle_key, owner_key,
             CommitmentAt(config, 1295, 1, 402), 409),
         GlobalRegistration(
             genesis, last, last_key, owner_key,
             CommitmentAt(config, 1295, 1, 403), 410)})};
    PQRegistryManager manager(MemoryDB(401), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295,
        Members(genesis, registered_hashes, registered_hashes,
                owner_key_id),
        {}, /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    BOOST_REQUIRE_EQUAL(parent.operator_states.size(), 3U);
    BOOST_CHECK(parent.FindOperator(absent) == nullptr);

    const std::vector<uint256> net_removed{first, absent, last};
    auto replacement_key{DeterministicKey(124)};
    const auto* first_state{parent.FindOperator(first)};
    BOOST_REQUIRE(first_state != nullptr);
    const auto conflicting_removal{Block(
        registration.GetHash(), 413,
        {OrdinaryTransaction(413),
         GlobalRotation(
             genesis, first, first_state->global_key, first_key,
             replacement_key, CommitmentAt(config, 1296, 2, 404), 414)})};
    const std::vector<uint256> conflicting_net_removed{first};
    BOOST_CHECK(!manager.ProcessBlock(
        conflicting_removal, 1296,
        Members(genesis, registered_hashes, {middle, last}, owner_key_id),
        conflicting_net_removed, /*fJustCheck=*/true, error));
    BOOST_CHECK(error.result == PQRegistryResult::DMN_REMOVED_IN_BLOCK);
    BOOST_CHECK_EQUAL(error.transaction_index, 1U);
    BOOST_CHECK(error.pro_tx_hash == first);

    const auto removed{Block(
        registration.GetHash(), 411, {OrdinaryTransaction(411)})};
    const auto removal_callbacks{Members(
        genesis, registered_hashes, {middle}, owner_key_id)};
    BOOST_REQUIRE(manager.ProcessBlock(
        removed, 1296, removal_callbacks, net_removed,
        /*fJustCheck=*/true, error));
    PQRegistrySnapshot missing;
    BOOST_CHECK(!manager.GetSnapshot(
        removed.GetHash(), registration.GetHash(), 1296, missing, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    BOOST_REQUIRE(manager.ProcessBlock(
        removed, 1296, removal_callbacks, net_removed,
        /*fJustCheck=*/false, error));
    PQRegistrySnapshot removed_snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        removed.GetHash(), registration.GetHash(), 1296, removed_snapshot,
        error));
    BOOST_REQUIRE_EQUAL(removed_snapshot.operator_states.size(), 1U);
    BOOST_CHECK(removed_snapshot.operator_states.front().pro_tx_hash ==
                middle);

    PQRegistryDiskSnapshot removed_delta;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        removed.GetHash(), removed_delta));
    const std::vector<uint256> expected_disk_removals{first, last};
    BOOST_CHECK(removed_delta.removed_operators == expected_disk_removals);

    const auto sibling{Block(
        registration.GetHash(), 412, {OrdinaryTransaction(412)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        sibling, 1296,
        Members(genesis, registered_hashes, registered_hashes,
                owner_key_id),
        {}, /*fJustCheck=*/false, error));
    PQRegistrySnapshot sibling_snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        sibling.GetHash(), registration.GetHash(), 1296, sibling_snapshot,
        error));
    BOOST_REQUIRE_EQUAL(sibling_snapshot.operator_states.size(), 3U);
    for (const auto& pro_tx_hash : registered_hashes) {
        BOOST_CHECK(sibling_snapshot.FindOperator(pro_tx_hash) != nullptr);
    }
    PQRegistryDiskSnapshot sibling_delta;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        sibling.GetHash(), sibling_delta));
    BOOST_CHECK(sibling_delta.removed_operators.empty());

    std::vector<uint256> rootless_before{registered_hashes};
    rootless_before.push_back(absent);
    std::sort(rootless_before.begin(), rootless_before.end());
    const auto rootless_removal{Block(
        sibling.GetHash(), 415, {OrdinaryTransaction(415)})};
    const std::vector<uint256> rootless_delta{absent};
    BOOST_REQUIRE(manager.ProcessBlock(
        rootless_removal, 1297,
        Members(genesis, rootless_before, registered_hashes, owner_key_id),
        rootless_delta, /*fJustCheck=*/false, error));
    PQRegistryReadView sibling_view;
    PQRegistryReadView rootless_view;
    BOOST_REQUIRE(manager.GetReadView(
        sibling.GetHash(), registration.GetHash(), 1296, sibling_view,
        error));
    BOOST_REQUIRE(manager.GetReadView(
        rootless_removal.GetHash(), sibling.GetHash(), 1297, rootless_view,
        error));
    BOOST_CHECK(sibling_view.SharesStateWith(rootless_view));
    BOOST_CHECK(sibling_view.SharesTreeHistoryWith(rootless_view));
    BOOST_CHECK(sibling_view.ConsensusStateRoot() ==
                rootless_view.ConsensusStateRoot());
    PQRegistryDiskSnapshot rootless_disk;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        rootless_removal.GetHash(), rootless_disk));
    BOOST_CHECK_EQUAL(rootless_disk.is_checkpoint, 0U);
    BOOST_CHECK(rootless_disk.operator_states.empty());
    BOOST_CHECK(rootless_disk.removed_operators.empty());
    BOOST_CHECK(rootless_disk.tree_ids.empty());
    BOOST_CHECK(rootless_disk.block_tree_ids.empty());
    BOOST_CHECK(rootless_disk.previous_consensus_state_root ==
                sibling_view.ConsensusStateRoot());
    BOOST_CHECK(rootless_disk.consensus_state_root ==
                rootless_view.ConsensusStateRoot());

    BOOST_CHECK(!manager.PreflightUndoBlock(
        rootless_removal.GetHash(), removed.GetHash(), 1297, error));
    BOOST_CHECK(error.result == PQRegistryResult::UNDO_MISMATCH);
    BOOST_REQUIRE(manager.PreflightUndoBlock(
        rootless_removal.GetHash(), sibling.GetHash(), 1297, error));

    BOOST_REQUIRE(manager.PreflightUndoBlock(
        removed.GetHash(), registration.GetHash(), 1296, error));
}

BOOST_AUTO_TEST_CASE(malformed_removal_spans_are_rejected)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(421)};
    PQRegistryManager manager(MemoryDB(421), genesis, config);
    PQRegistryError error;
    const auto block{Block(
        NonNullHash(422), 423, {OrdinaryTransaction(423)})};
    const auto callbacks{Members(genesis, {}, {}, CKeyID{})};

    const std::vector<uint256> null_removal{uint256{}};
    BOOST_CHECK(!manager.ProcessBlock(
        block, config.preparation_height + 1, callbacks, null_removal,
        /*fJustCheck=*/true, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);

    const uint256 duplicate{NonNullHash(424)};
    const std::vector<uint256> duplicate_removals{duplicate, duplicate};
    BOOST_CHECK(!manager.ProcessBlock(
        block, config.preparation_height + 1, callbacks,
        duplicate_removals, /*fJustCheck=*/true, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);

    std::vector<uint256> descending{
        NonNullHash(425), NonNullHash(426)};
    std::sort(descending.rbegin(), descending.rend());
    BOOST_CHECK(!manager.ProcessBlock(
        block, config.preparation_height + 1, callbacks, descending,
        /*fJustCheck=*/true, error));
    BOOST_CHECK(error.result == PQRegistryResult::INTERNAL_ERROR);
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
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id), {},
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
        revoke, 1296, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
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
        recovery, 1297, Member(genesis, pro_tx_hash, owner_key_id), {}, true,
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
    uint256 steady_hash;
    uint256 checkpoint_grandparent_hash;
    uint256 checkpoint_previous_hash;
    uint256 checkpoint_hash;

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
            Member(genesis, pro_tx_hash, owner_key_id), {}, false, error));
        registration_hash = registration.GetHash();
        const auto cutoff{Block(registration_hash, 72,
                                {OrdinaryTransaction(72)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            cutoff, 1296, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
            error));
        cutoff_hash = cutoff.GetHash();
        const auto steady{Block(cutoff_hash, 74,
                                {OrdinaryTransaction(74)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            steady, 1297, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
            error));
        BOOST_REQUIRE(manager.ProcessBlock(
            steady, 1297, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
            error));
        steady_hash = steady.GetHash();
        BOOST_REQUIRE(manager.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    {
        PQRegistryManager restarted(db, genesis, config);
        PQRegistryError error;
        PQRegistrySnapshot snapshot;
        BOOST_REQUIRE(restarted.GetSnapshot(
            steady_hash, cutoff_hash, 1297, snapshot, error));
        BOOST_CHECK(snapshot.HasUsedTreeId(commitment.tree_id));
        const auto frozen{OnlyOperator(snapshot).ResolveChildRoot(0)};
        BOOST_REQUIRE(frozen.record);
        BOOST_CHECK(frozen.status ==
                    ChildRootResolutionStatus::FROZEN_PRESENT);
        BOOST_CHECK(frozen.record->commitment == commitment);
        BOOST_CHECK(snapshot.RecomputeConsensusStateRoot(genesis) ==
                    snapshot.consensus_state_root);

        uint256 cursor{steady_hash};
        uint32_t block_id{75};
        CBlock checkpoint;
        for (int32_t height{1298};
             height <= config.preparation_height +
                           PQ_REGISTRY_CHECKPOINT_INTERVAL;
             ++height) {
            auto next{Block(cursor, block_id,
                            {OrdinaryTransaction(block_id)})};
            ++block_id;
            BOOST_REQUIRE(restarted.ProcessBlock(
                next, height,
                Member(genesis, pro_tx_hash, owner_key_id), {}, false,
                error));
            cursor = next.GetHash();
            if (height == config.preparation_height +
                              PQ_REGISTRY_CHECKPOINT_INTERVAL - 1) {
                checkpoint_grandparent_hash = next.hashPrevBlock;
                checkpoint_previous_hash = cursor;
            } else if (height == config.preparation_height +
                                     PQ_REGISTRY_CHECKPOINT_INTERVAL) {
                checkpoint = std::move(next);
                checkpoint_hash = cursor;
            }
        }

        const auto before_checkpoint_schedule{
            DeriveOperatorKeyScheduleView(
                config.schedule,
                config.preparation_height +
                    PQ_REGISTRY_CHECKPOINT_INTERVAL - 1,
                config.registration_cutoff_blocks,
                config.future_horizon_epochs)};
        const auto checkpoint_schedule{DeriveOperatorKeyScheduleView(
            config.schedule,
            config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL,
            config.registration_cutoff_blocks,
            config.future_horizon_epochs)};
        BOOST_REQUIRE(before_checkpoint_schedule);
        BOOST_REQUIRE(checkpoint_schedule);
        BOOST_REQUIRE(OperatorKeyScheduleState::FromView(
                          *before_checkpoint_schedule) ==
                      OperatorKeyScheduleState::FromView(
                          *checkpoint_schedule));

        PQRegistryReadView before_checkpoint_view;
        PQRegistryReadView checkpoint_view;
        BOOST_REQUIRE(restarted.GetReadView(
            checkpoint_previous_hash, checkpoint_grandparent_hash,
            config.preparation_height +
                PQ_REGISTRY_CHECKPOINT_INTERVAL - 1,
            before_checkpoint_view, error));
        BOOST_REQUIRE(restarted.GetReadView(
            checkpoint_hash, checkpoint_previous_hash,
            config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL,
            checkpoint_view, error));
        BOOST_CHECK(before_checkpoint_view.SharesStateWith(checkpoint_view));

        PQRegistryDiskSnapshot checkpoint_disk;
        BOOST_REQUIRE(restarted.SnapshotDatabase().ReadCache(
            checkpoint_hash, checkpoint_disk));
        BOOST_CHECK_EQUAL(checkpoint_disk.is_checkpoint, 1U);
        BOOST_CHECK(checkpoint_disk.operator_states.empty());
        BOOST_REQUIRE_EQUAL(
            checkpoint_disk.checkpoint_operator_states.size(), 1U);
        BOOST_REQUIRE_EQUAL(checkpoint_disk.tree_ids.size(), 1U);
        BOOST_CHECK(checkpoint_disk.block_tree_ids.empty());

        BOOST_REQUIRE(restarted.ProcessBlock(
            checkpoint,
            config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL,
            Member(genesis, pro_tx_hash, owner_key_id), {}, false, error));
        BOOST_REQUIRE(restarted.Flush(/*fSync=*/true));
    }

    PQRegistryManager checkpoint_restarted(db, genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(checkpoint_restarted.PreflightUndoBlock(
        checkpoint_hash, checkpoint_previous_hash,
        config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL,
        error));
    PQRegistrySnapshot checkpoint_snapshot;
    BOOST_REQUIRE(checkpoint_restarted.GetSnapshot(
        checkpoint_hash, checkpoint_previous_hash,
        config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL,
        checkpoint_snapshot, error));
    BOOST_CHECK(checkpoint_snapshot.HasUsedTreeId(commitment.tree_id));
    BOOST_CHECK(checkpoint_snapshot.RecomputeConsensusStateRoot(genesis) ==
                checkpoint_snapshot.consensus_state_root);
}

BOOST_AUTO_TEST_CASE(cold_reconstruction_reuses_long_no_op_suffix)
{
    auto config{Config()};
    config.schedule.epoch_origin = 10'080;
    BOOST_REQUIRE(config.IsValid());
    const uint256 genesis{NonNullHash(691)};
    const uint256 journal_parent{NonNullHash(692)};
    auto db{MemoryDB(691)};
    db.path = m_path_root / "pq_registry_cold_no_op_suffix";
    db.memory_only = false;

    constexpr std::size_t record_count{96};
    std::vector<uint256> hashes;
    hashes.reserve(record_count);
    {
        PQRegistryManager writer(db, genesis, config);
        PQRegistryError error;
        const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
        uint256 cursor{journal_parent};
        for (std::size_t offset{0}; offset < record_count; ++offset) {
            const uint32_t id{89'000 + static_cast<uint32_t>(offset)};
            const auto block{Block(
                cursor, id, {OrdinaryTransaction(id)})};
            BOOST_REQUIRE(writer.ProcessBlock(
                block,
                config.preparation_height + static_cast<int32_t>(offset),
                callbacks, {}, /*fJustCheck=*/false, error));
            hashes.push_back(block.GetHash());
            cursor = block.GetHash();
        }
        BOOST_REQUIRE(writer.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    PQRegistryManager reader(db, genesis, config);
    test::PQRegistryManagerTestAccess::ResetReconstructionStats(reader);
    PQRegistryError error;
    PQRegistryReadView tip;
    BOOST_REQUIRE(reader.GetReadView(
        hashes.back(), hashes[hashes.size() - 2],
        config.preparation_height + static_cast<int32_t>(record_count) - 1,
        tip, error));
    const auto stats{test::PQRegistryManagerTestAccess::Stats(reader)};
    BOOST_CHECK_EQUAL(stats.authenticated_records, record_count);
    BOOST_CHECK_EQUAL(stats.reused_records, record_count - 1);
    BOOST_CHECK_EQUAL(stats.tree_id_hashes, 1U);
    BOOST_CHECK_EQUAL(stats.state_hashes, 1U);
    BOOST_CHECK_EQUAL(stats.cached_views,
                      PQ_REGISTRY_SNAPSHOT_CACHE_SIZE);

    PQRegistryReadView parent;
    BOOST_REQUIRE(reader.GetReadView(
        hashes[hashes.size() - 2], hashes[hashes.size() - 3],
        config.preparation_height + static_cast<int32_t>(record_count) - 2,
        parent, error));
    BOOST_CHECK(tip.SharesStateWith(parent));
    BOOST_CHECK(tip.SharesTreeHistoryWith(parent));
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(reader)
            .authenticated_records,
        record_count);
}

BOOST_AUTO_TEST_CASE(cold_reconstruction_has_exact_two_interval_bound)
{
    auto config{Config()};
    config.schedule.epoch_origin = 10'080;
    BOOST_REQUIRE(config.IsValid());
    const uint256 genesis{NonNullHash(696)};
    const uint256 journal_parent{NonNullHash(697)};
    auto db{MemoryDB(696)};
    db.path = m_path_root / "pq_registry_two_interval_bound";
    db.memory_only = false;

    constexpr std::size_t record_count{
        2U * static_cast<std::size_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    const int32_t target_height{
        config.preparation_height + static_cast<int32_t>(record_count) - 1};
    uint256 target_hash;
    uint256 target_parent;
    PQRegistrySnapshot expected;
    {
        PQRegistryManager writer(db, genesis, config);
        PQRegistryError error;
        const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
        uint256 cursor{journal_parent};
        for (std::size_t offset{0}; offset < record_count; ++offset) {
            const uint32_t id{89'500 + static_cast<uint32_t>(offset)};
            const auto block{Block(
                cursor, id, {OrdinaryTransaction(id)})};
            BOOST_REQUIRE(writer.ProcessBlock(
                block,
                config.preparation_height +
                    static_cast<int32_t>(offset),
                callbacks, {}, /*fJustCheck=*/false, error));
            target_parent = cursor;
            cursor = block.GetHash();
        }
        target_hash = cursor;
        BOOST_REQUIRE(writer.GetSnapshot(
            target_hash, target_parent, target_height, expected, error));
        BOOST_REQUIRE(writer.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    PQRegistryManager reader(db, genesis, config);
    test::PQRegistryManagerTestAccess::ResetReconstructionStats(reader);
    PQRegistryError error;
    PQRegistrySnapshot reconstructed;
    BOOST_REQUIRE(reader.GetSnapshot(
        target_hash, target_parent, target_height, reconstructed, error));
    BOOST_CHECK(reconstructed == expected);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(reader)
            .authenticated_records,
        record_count);
}

BOOST_AUTO_TEST_CASE(cold_sequential_undo_reuses_authenticated_replay_tail)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(701)};
    const uint256 pro_tx_hash{NonNullHash(702)};
    const uint256 journal_parent{NonNullHash(703)};
    auto key{DeterministicKey(91)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto commitment{CommitmentAt(
        config, config.preparation_height, 1, 701)};
    auto db{MemoryDB(701)};
    db.path = m_path_root / "pq_registry_cold_sequential_undo";
    db.memory_only = false;

    constexpr std::size_t record_count{
        static_cast<std::size_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL)};
    std::vector<uint256> hashes;
    std::vector<uint256> roots;
    hashes.reserve(record_count);
    roots.reserve(record_count);
    {
        PQRegistryManager writer(db, genesis, config);
        PQRegistryError error;
        uint256 cursor{journal_parent};
        for (std::size_t offset{0}; offset < record_count; ++offset) {
            const int32_t height{
                config.preparation_height + static_cast<int32_t>(offset)};
            const uint32_t id{90'000 + static_cast<uint32_t>(offset)};
            std::vector<CTransactionRef> transactions{
                OrdinaryTransaction(id)};
            if (offset == 0) {
                transactions.push_back(GlobalRegistration(
                    genesis, pro_tx_hash, key, owner_key, commitment,
                    id + 1'000));
            }
            const auto block{Block(cursor, id, std::move(transactions))};
            uint256 root;
            BOOST_REQUIRE(writer.ProcessBlock(
                block, height,
                Member(genesis, pro_tx_hash, owner_key_id), {},
                /*fJustCheck=*/false, error, &root));
            BOOST_REQUIRE(!root.IsNull());
            hashes.push_back(block.GetHash());
            roots.push_back(root);
            cursor = block.GetHash();
        }
        BOOST_REQUIRE(writer.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    PQRegistryManager reader(db, genesis, config);
    test::PQRegistryManagerTestAccess::ResetReconstructionStats(reader);
    PQRegistryError error;
    for (std::size_t remaining{record_count}; remaining > 0; --remaining) {
        const std::size_t index{remaining - 1};
        const uint256& parent{
            index == 0 ? journal_parent : hashes[index - 1]};
        BOOST_REQUIRE(reader.PreflightUndoBlock(
            hashes[index], parent,
            config.preparation_height + static_cast<int32_t>(index), error));
        if (index == record_count - 1) {
            const auto first_stats{
                test::PQRegistryManagerTestAccess::Stats(reader)};
            BOOST_CHECK_EQUAL(first_stats.authenticated_records,
                              record_count);
            BOOST_CHECK_EQUAL(first_stats.cached_views,
                              PQ_REGISTRY_SNAPSHOT_CACHE_SIZE);
        }
    }

    uint64_t expected_authentications{0};
    for (std::size_t remaining{record_count}; remaining > 0;) {
        expected_authentications += remaining;
        if (remaining <= PQ_REGISTRY_SNAPSHOT_CACHE_SIZE) break;
        remaining -= PQ_REGISTRY_SNAPSHOT_CACHE_SIZE;
    }
    BOOST_CHECK_EQUAL(expected_authentications, 800U);
    const auto stats{test::PQRegistryManagerTestAccess::Stats(reader)};
    BOOST_CHECK_EQUAL(stats.authenticated_records,
                      expected_authentications);
    BOOST_CHECK_LE(stats.cached_views, PQ_REGISTRY_SNAPSHOT_CACHE_SIZE);

    PQRegistryReadView preparation;
    PQRegistryReadView cutoff;
    PQRegistryReadView steady;
    BOOST_REQUIRE(reader.GetReadView(
        hashes[0], journal_parent, config.preparation_height,
        preparation, error));
    BOOST_REQUIRE(reader.GetReadView(
        hashes[1], hashes[0], config.preparation_height + 1,
        cutoff, error));
    BOOST_REQUIRE(reader.GetReadView(
        hashes[2], hashes[1], config.preparation_height + 2,
        steady, error));
    BOOST_CHECK(preparation.ConsensusStateRoot() == roots[0]);
    BOOST_CHECK(cutoff.ConsensusStateRoot() == roots[1]);
    BOOST_CHECK(steady.ConsensusStateRoot() == roots[2]);
    BOOST_CHECK(!preparation.SharesStateWith(cutoff));
    BOOST_CHECK(cutoff.SharesStateWith(steady));
    BOOST_CHECK(preparation.SharesTreeHistoryWith(cutoff));
    BOOST_CHECK(cutoff.SharesTreeHistoryWith(steady));
    BOOST_CHECK_EQUAL(preparation.OperatorCount(), 1U);
    BOOST_CHECK_EQUAL(cutoff.OperatorCount(), 1U);
    BOOST_CHECK_EQUAL(steady.OperatorCount(), 1U);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(reader)
            .authenticated_records,
        expected_authentications);
}

BOOST_AUTO_TEST_CASE(corrupt_reconstruction_does_not_publish_replay_prefix)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(711)};
    const uint256 journal_parent{NonNullHash(712)};
    auto db{MemoryDB(711)};
    db.path = m_path_root / "pq_registry_corrupt_replay_prefix";
    db.memory_only = false;
    constexpr std::size_t record_count{8};
    std::vector<uint256> hashes;
    hashes.reserve(record_count);
    {
        PQRegistryManager writer(db, genesis, config);
        PQRegistryError error;
        const auto callbacks{Members(genesis, {}, {}, CKeyID{})};
        uint256 cursor{journal_parent};
        for (std::size_t offset{0}; offset < record_count; ++offset) {
            const uint32_t id{91'000 + static_cast<uint32_t>(offset)};
            const auto block{Block(
                cursor, id, {OrdinaryTransaction(id)})};
            BOOST_REQUIRE(writer.ProcessBlock(
                block,
                config.preparation_height + static_cast<int32_t>(offset),
                callbacks, {}, /*fJustCheck=*/false, error));
            hashes.push_back(block.GetHash());
            cursor = block.GetHash();
        }
        PQRegistryDiskSnapshot corrupt;
        BOOST_REQUIRE(writer.SnapshotDatabase().ReadCache(
            hashes.back(), corrupt));
        corrupt.consensus_state_root.begin()[0] ^= 1;
        BOOST_REQUIRE(writer.SnapshotDatabase().WriteThrough(
            hashes.back(), corrupt, /*fSync=*/true));
        BOOST_REQUIRE(writer.Flush(/*fSync=*/true));
    }

    db.wipe_data = false;
    PQRegistryManager reader(db, genesis, config);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(reader).cached_views, 0U);
    PQRegistryError error;
    PQRegistrySnapshot rejected;
    BOOST_CHECK(!reader.GetSnapshot(
        hashes.back(), hashes[hashes.size() - 2],
        config.preparation_height + static_cast<int32_t>(record_count) - 1,
        rejected, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);
    const auto stats{test::PQRegistryManagerTestAccess::Stats(reader)};
    BOOST_CHECK_EQUAL(stats.authenticated_records, record_count - 1);
    BOOST_CHECK_EQUAL(stats.cached_views, 0U);
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
        registration, 1295, Member(genesis, pro_tx_hash, owner_key_id), {},
        false, error));
    const auto child{Block(registration.GetHash(), 102,
                           {OrdinaryTransaction(102)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        child, 1296, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
        error));

    PQRegistryDiskSnapshot corrupt;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        child.GetHash(), corrupt));
    corrupt.previous_consensus_state_root = NonNullHash(104);
    BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
        child.GetHash(), corrupt, /*fSync=*/true));
    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, child.GetHash());

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
        early, 1294, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
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
        Member(genesis, pro_tx_hash, owner_key_id), {}, false, error));
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
        mismatch, 1295, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
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
               /*owner_authorized=*/false), {},
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
        duplicate, 1295, Member(genesis, pro_tx_hash, owner_key_id), {}, false,
        error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::DUPLICATE_OPERATOR_UPDATE);
    BOOST_CHECK_EQUAL(error.transaction_index, 2U);
    BOOST_CHECK(error.pro_tx_hash == pro_tx_hash);
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
        duplicate_key_block, 1295, callbacks, {}, false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(error.transaction_index, 2U);
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
        duplicate_tree_block, 1295, callbacks, {}, false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::DUPLICATE_CHILD_TREE_ID);
    BOOST_CHECK_EQUAL(error.transaction_index, 2U);
    BOOST_CHECK(error.pro_tx_hash == second);
}

BOOST_AUTO_TEST_CASE(batch_overlay_global_key_handoffs_are_ordered)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(501)};
    std::vector<uint256> operators{
        NonNullHash(502), NonNullHash(503), NonNullHash(504)};
    std::sort(operators.begin(), operators.end());
    const uint256& first{operators[0]};
    const uint256& second{operators[1]};
    const uint256& third{operators[2]};

    auto first_key{DeterministicKey(131)};
    auto second_key{DeterministicKey(132)};
    auto third_key{DeterministicKey(133)};
    auto replacement_key{DeterministicKey(134)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto first_tree{CommitmentAt(config, 1295, 1, 501)};
    const auto second_tree{CommitmentAt(config, 1295, 1, 502)};
    const auto third_tree{CommitmentAt(config, 1295, 1, 503)};
    const auto registration{Block(
        NonNullHash(505), 506,
        {OrdinaryTransaction(506),
         GlobalRegistration(
             genesis, first, first_key, owner_key, first_tree, 507),
         GlobalRegistration(
             genesis, second, second_key, owner_key, second_tree, 508),
         GlobalRegistration(
             genesis, third, third_key, owner_key, third_tree, 509)})};
    const auto callbacks{Members(
        genesis, operators, operators, owner_key_id)};
    PQRegistryManager manager(MemoryDB(501), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295, callbacks, {}, /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    const GlobalKeyRecord first_current{
        RequiredOperator(parent, first).global_key};
    const GlobalKeyRecord second_current{
        RequiredOperator(parent, second).global_key};
    const GlobalKeyRecord third_current{
        RequiredOperator(parent, third).global_key};

    const auto first_next_tree{CommitmentAt(config, 1296, 2, 504)};
    const auto second_next_tree{CommitmentAt(config, 1296, 2, 505)};
    const auto first_to_replacement{GlobalRotation(
        genesis, first, first_current, first_key, replacement_key,
        first_next_tree, 510)};
    const auto second_to_first{GlobalRotation(
        genesis, second, second_current, second_key, first_key,
        second_next_tree, 511)};

    const auto forward{Block(
        registration.GetHash(), 512,
        {OrdinaryTransaction(512), first_to_replacement,
         second_to_first})};
    BOOST_REQUIRE(manager.ProcessBlock(
        forward, 1296, callbacks, {}, /*fJustCheck=*/false, error));
    PQRegistrySnapshot forward_snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        forward.GetHash(), registration.GetHash(), 1296, forward_snapshot,
        error));
    GlobalPublicKey replacement_public_key;
    BOOST_REQUIRE(replacement_key.GetPublicKey(replacement_public_key));
    GlobalPublicKey first_public_key;
    BOOST_REQUIRE(first_key.GetPublicKey(first_public_key));
    BOOST_CHECK(RequiredOperator(forward_snapshot, first)
                    .global_key.public_key == replacement_public_key);
    BOOST_CHECK(RequiredOperator(forward_snapshot, second)
                    .global_key.public_key == first_public_key);

    const auto reverse{Block(
        registration.GetHash(), 513,
        {OrdinaryTransaction(513), second_to_first,
         first_to_replacement})};
    BOOST_CHECK(!manager.ProcessBlock(
        reverse, 1296, callbacks, {}, /*fJustCheck=*/false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(error.transaction_index, 1U);
    BOOST_CHECK(error.pro_tx_hash == second);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(reverse.GetHash()));

    const auto first_to_second{GlobalRotation(
        genesis, first, first_current, first_key, second_key,
        CommitmentAt(config, 1296, 2, 506), 514)};
    const auto swap{Block(
        registration.GetHash(), 515,
        {OrdinaryTransaction(515), first_to_second, second_to_first})};
    BOOST_CHECK(!manager.ProcessBlock(
        swap, 1296, callbacks, {}, /*fJustCheck=*/false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(error.transaction_index, 1U);
    BOOST_CHECK(error.pro_tx_hash == first);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(swap.GetHash()));

    const auto third_to_first{GlobalRotation(
        genesis, third, third_current, third_key, first_key,
        CommitmentAt(config, 1296, 2, 507), 516)};
    const auto third_claimant{Block(
        registration.GetHash(), 517,
        {OrdinaryTransaction(517), first_to_replacement,
         second_to_first, third_to_first})};
    BOOST_CHECK(!manager.ProcessBlock(
        third_claimant, 1296, callbacks, {}, /*fJustCheck=*/false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(error.transaction_index, 3U);
    BOOST_CHECK(error.pro_tx_hash == third);
    BOOST_CHECK(
        !manager.SnapshotDatabase().ExistsCache(third_claimant.GetHash()));
}

BOOST_AUTO_TEST_CASE(removal_releases_global_key_next_block_but_not_tree_id)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(521)};
    std::vector<uint256> operators{NonNullHash(522), NonNullHash(523)};
    std::sort(operators.begin(), operators.end());
    const uint256& removed_operator{operators[0]};
    const uint256& surviving_operator{operators[1]};
    auto removed_key{DeterministicKey(141)};
    auto surviving_key{DeterministicKey(142)};
    auto unused_key{DeterministicKey(143)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto removed_tree{CommitmentAt(config, 1295, 1, 521)};
    const auto surviving_tree{CommitmentAt(config, 1295, 1, 522)};
    const auto registration{Block(
        NonNullHash(524), 525,
        {OrdinaryTransaction(525),
         GlobalRegistration(genesis, removed_operator, removed_key,
                            owner_key, removed_tree, 526),
         GlobalRegistration(genesis, surviving_operator, surviving_key,
                            owner_key, surviving_tree, 527)})};
    PQRegistryManager manager(MemoryDB(521), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295,
        Members(genesis, operators, operators, owner_key_id), {},
        /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    const GlobalKeyRecord surviving_current{
        RequiredOperator(parent, surviving_operator).global_key};
    const auto same_block_claim{GlobalRotation(
        genesis, surviving_operator, surviving_current, surviving_key,
        removed_key, CommitmentAt(config, 1296, 2, 523), 528)};
    const auto claim_while_removing{Block(
        registration.GetHash(), 529,
        {OrdinaryTransaction(529), same_block_claim})};
    const std::vector<uint256> net_removed{removed_operator};
    const auto removal_callbacks{Members(
        genesis, operators, {surviving_operator}, owner_key_id)};
    BOOST_CHECK(!manager.ProcessBlock(
        claim_while_removing, 1296, removal_callbacks, net_removed,
        /*fJustCheck=*/false, error));
    BOOST_CHECK(error.result == PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(error.transaction_index, 1U);
    BOOST_CHECK(error.pro_tx_hash == surviving_operator);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(
        claim_while_removing.GetHash()));

    const auto removal{Block(
        registration.GetHash(), 530, {OrdinaryTransaction(530)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        removal, 1296, removal_callbacks, net_removed,
        /*fJustCheck=*/false, error));
    PQRegistrySnapshot after_removal;
    BOOST_REQUIRE(manager.GetSnapshot(
        removal.GetHash(), registration.GetHash(), 1296, after_removal,
        error));
    BOOST_CHECK(after_removal.FindOperator(removed_operator) == nullptr);
    BOOST_CHECK(after_removal.HasUsedTreeId(removed_tree.tree_id));
    BOOST_CHECK(after_removal.HasUsedTreeId(surviving_tree.tree_id));

    const GlobalKeyRecord surviving_after_removal{
        RequiredOperator(after_removal, surviving_operator).global_key};
    const auto claimed_tree{CommitmentAt(config, 1297, 2, 524)};
    const auto next_block_claim{GlobalRotation(
        genesis, surviving_operator, surviving_after_removal,
        surviving_key, removed_key, claimed_tree, 531)};
    const auto claimed{Block(
        removal.GetHash(), 532,
        {OrdinaryTransaction(532), next_block_claim})};
    const auto surviving_callbacks{Member(
        genesis, surviving_operator, owner_key_id)};
    BOOST_REQUIRE(manager.ProcessBlock(
        claimed, 1297, surviving_callbacks, {}, /*fJustCheck=*/false,
        error));
    PQRegistrySnapshot claimed_snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        claimed.GetHash(), removal.GetHash(), 1297, claimed_snapshot,
        error));
    GlobalPublicKey removed_public_key;
    BOOST_REQUIRE(removed_key.GetPublicKey(removed_public_key));
    BOOST_CHECK(RequiredOperator(claimed_snapshot, surviving_operator)
                    .global_key.public_key == removed_public_key);
    BOOST_CHECK(claimed_snapshot.HasUsedTreeId(removed_tree.tree_id));
    BOOST_CHECK(claimed_snapshot.HasUsedTreeId(surviving_tree.tree_id));
    BOOST_CHECK(claimed_snapshot.HasUsedTreeId(claimed_tree.tree_id));

    auto reused_tree{CommitmentAt(config, 1297, 2, 525)};
    reused_tree.tree_id = removed_tree.tree_id;
    BOOST_REQUIRE(reused_tree.IsStructurallyValid());
    const auto burned_tree_claim{GlobalRotation(
        genesis, surviving_operator, surviving_after_removal,
        surviving_key, unused_key, reused_tree, 533)};
    const auto burned_tree_sibling{Block(
        removal.GetHash(), 534,
        {OrdinaryTransaction(534), burned_tree_claim})};
    BOOST_CHECK(!manager.ProcessBlock(
        burned_tree_sibling, 1297, surviving_callbacks, {},
        /*fJustCheck=*/false, error));
    BOOST_CHECK(error.result ==
                PQRegistryResult::DUPLICATE_CHILD_TREE_ID);
    BOOST_CHECK_EQUAL(error.transaction_index, 1U);
    BOOST_CHECK(error.pro_tx_hash == surviving_operator);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(
        burned_tree_sibling.GetHash()));
}

BOOST_AUTO_TEST_CASE(mixed_batch_merge_is_canonical_across_permutations)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(541)};
    std::vector<uint256> operators{
        NonNullHash(542), NonNullHash(543), NonNullHash(544),
        NonNullHash(545)};
    std::sort(operators.begin(), operators.end());
    const uint256& first{operators[0]};
    const uint256& removed{operators[1]};
    const uint256& added{operators[2]};
    const uint256& last{operators[3]};
    const std::vector<uint256> parent_operators{first, removed, last};
    const std::vector<uint256> resulting_operators{first, added, last};

    auto first_key{DeterministicKey(151)};
    auto removed_key{DeterministicKey(152)};
    auto added_key{DeterministicKey(153)};
    auto last_key{DeterministicKey(154)};
    auto first_replacement{DeterministicKey(155)};
    auto last_replacement{DeterministicKey(156)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto first_tree{CommitmentAt(config, 1295, 1, 541)};
    const auto removed_tree{CommitmentAt(config, 1295, 1, 542)};
    const auto last_tree{CommitmentAt(config, 1295, 1, 543)};
    const auto registration{Block(
        NonNullHash(546), 547,
        {OrdinaryTransaction(547),
         GlobalRegistration(
             genesis, first, first_key, owner_key, first_tree, 548),
         GlobalRegistration(genesis, removed, removed_key, owner_key,
                            removed_tree, 549),
         GlobalRegistration(
             genesis, last, last_key, owner_key, last_tree, 550)})};
    PQRegistryManager manager(MemoryDB(541), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295,
        Members(genesis, parent_operators, parent_operators, owner_key_id),
        {}, /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    const GlobalKeyRecord first_current{
        RequiredOperator(parent, first).global_key};
    const GlobalKeyRecord last_current{
        RequiredOperator(parent, last).global_key};
    const auto first_next_tree{CommitmentAt(config, 1296, 2, 544)};
    const auto added_tree{CommitmentAt(config, 1296, 1, 545)};
    const auto last_next_tree{CommitmentAt(config, 1296, 2, 546)};
    const auto update_first{GlobalRotation(
        genesis, first, first_current, first_key, first_replacement,
        first_next_tree, 551)};
    const auto add_middle{GlobalRegistration(
        genesis, added, added_key, owner_key, added_tree, 552)};
    const auto update_last{GlobalRotation(
        genesis, last, last_current, last_key, last_replacement,
        last_next_tree, 553)};
    const auto callbacks{Members(
        genesis, operators, resulting_operators, owner_key_id)};
    const std::vector<uint256> net_removed{removed};
    const auto descending{Block(
        registration.GetHash(), 554,
        {OrdinaryTransaction(554), update_last, add_middle,
         update_first})};
    const auto ascending{Block(
        registration.GetHash(), 555,
        {OrdinaryTransaction(555), update_first, add_middle,
         update_last})};

    PQRegistryPreparedBlock descending_prepared;
    PQRegistryPreparedBlock ascending_prepared;
    BOOST_REQUIRE(manager.PrepareBlock(
        descending, 1296, callbacks, net_removed, descending_prepared,
        error));
    BOOST_REQUIRE(manager.PrepareBlock(
        ascending, 1296, callbacks, net_removed, ascending_prepared,
        error));
    BOOST_CHECK(descending_prepared.ConsensusStateRoot() ==
                ascending_prepared.ConsensusStateRoot());
    const uint256 prepared_root{
        descending_prepared.ConsensusStateRoot()};
    BOOST_REQUIRE(manager.CommitPreparedBlock(ascending_prepared, error));
    BOOST_CHECK(!ascending_prepared.IsValid());
    BOOST_CHECK(descending_prepared.IsValid());
    BOOST_CHECK(descending_prepared.ConsensusStateRoot() == prepared_root);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(
        descending.GetHash()));
    BOOST_REQUIRE(manager.CommitPreparedBlock(descending_prepared, error));
    BOOST_CHECK(!descending_prepared.IsValid());

    PQRegistrySnapshot descending_snapshot;
    PQRegistrySnapshot ascending_snapshot;
    BOOST_REQUIRE(manager.GetSnapshot(
        descending.GetHash(), registration.GetHash(), 1296,
        descending_snapshot, error));
    BOOST_REQUIRE(manager.GetSnapshot(
        ascending.GetHash(), registration.GetHash(), 1296,
        ascending_snapshot, error));
    BOOST_CHECK(descending_snapshot.operator_states ==
                ascending_snapshot.operator_states);
    BOOST_CHECK(descending_snapshot.used_tree_ids ==
                ascending_snapshot.used_tree_ids);
    BOOST_CHECK(descending_snapshot.block_tree_ids ==
                ascending_snapshot.block_tree_ids);
    BOOST_CHECK(descending_snapshot.consensus_state_root ==
                ascending_snapshot.consensus_state_root);

    std::vector<uint256> actual_operators;
    for (const auto& state : descending_snapshot.operator_states) {
        actual_operators.push_back(state.pro_tx_hash);
    }
    BOOST_CHECK(actual_operators == resulting_operators);
    BOOST_CHECK(descending_snapshot.FindOperator(removed) == nullptr);
    auto expected_first{Candidate(
        first_replacement, first_current.key_version + 1,
        first_next_tree)};
    expected_first.activated_height = 1296;
    auto expected_added{Candidate(added_key, 1, added_tree)};
    expected_added.activated_height = 1296;
    auto expected_last{Candidate(
        last_replacement, last_current.key_version + 1,
        last_next_tree)};
    expected_last.activated_height = 1296;
    BOOST_CHECK(RequiredOperator(descending_snapshot, first).global_key ==
                expected_first);
    BOOST_CHECK(RequiredOperator(descending_snapshot, added).global_key ==
                expected_added);
    BOOST_CHECK(RequiredOperator(descending_snapshot, last).global_key ==
                expected_last);

    std::vector<uint256> expected_new_tree_ids{
        first_next_tree.tree_id, added_tree.tree_id,
        last_next_tree.tree_id};
    std::sort(expected_new_tree_ids.begin(), expected_new_tree_ids.end());
    BOOST_CHECK(descending_snapshot.block_tree_ids == expected_new_tree_ids);
    std::vector<uint256> expected_used_tree_ids{
        first_tree.tree_id, removed_tree.tree_id, last_tree.tree_id,
        first_next_tree.tree_id, added_tree.tree_id,
        last_next_tree.tree_id};
    std::sort(expected_used_tree_ids.begin(), expected_used_tree_ids.end());
    BOOST_CHECK(descending_snapshot.used_tree_ids == expected_used_tree_ids);

    const auto check_disk_delta = [&](const CBlock& block) {
        PQRegistryDiskSnapshot disk;
        BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
            block.GetHash(), disk));
        BOOST_CHECK_EQUAL(disk.is_checkpoint, 0U);
        BOOST_CHECK(disk.tree_ids.empty());
        BOOST_CHECK(disk.removed_operators ==
                    std::vector<uint256>{removed});
        std::vector<uint256> changed_operators;
        for (const auto& state : disk.operator_states) {
            changed_operators.push_back(state.pro_tx_hash);
        }
        BOOST_CHECK(changed_operators == resulting_operators);
        BOOST_CHECK(disk.block_tree_ids == expected_new_tree_ids);
        BOOST_CHECK(disk.previous_consensus_state_root ==
                    parent.consensus_state_root);
        BOOST_CHECK(disk.consensus_state_root ==
                    descending_snapshot.consensus_state_root);
    };
    check_disk_delta(descending);
    check_disk_delta(ascending);

    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, descending.GetHash());
    PQRegistrySnapshot reconstructed_descending;
    BOOST_REQUIRE(manager.GetSnapshot(
        descending.GetHash(), registration.GetHash(), 1296,
        reconstructed_descending, error));
    BOOST_CHECK(reconstructed_descending == descending_snapshot);

    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, ascending.GetHash());
    PQRegistrySnapshot reconstructed_ascending;
    BOOST_REQUIRE(manager.GetSnapshot(
        ascending.GetHash(), registration.GetHash(), 1296,
        reconstructed_ascending, error));
    BOOST_CHECK(reconstructed_ascending == ascending_snapshot);

    PQRegistryDiskSnapshot original_descending;
    PQRegistryDiskSnapshot original_ascending;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        descending.GetHash(), original_descending));
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        ascending.GetHash(), original_ascending));

    auto overlapping{original_descending};
    overlapping.operator_states.push_back(
        RequiredOperator(parent, removed));
    std::sort(overlapping.operator_states.begin(),
              overlapping.operator_states.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    BOOST_CHECK(!overlapping.IsStructurallyValid());

    auto duplicate{original_descending};
    duplicate.operator_states.push_back(duplicate.operator_states.front());
    std::sort(duplicate.operator_states.begin(),
              duplicate.operator_states.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    BOOST_CHECK(!duplicate.IsStructurallyValid());

    auto missing_removal{original_descending};
    missing_removal.removed_operators = {NonNullHash(999'999)};
    auto missing_removal_result{descending_snapshot};
    missing_removal_result.operator_states.push_back(
        RequiredOperator(parent, removed));
    std::sort(missing_removal_result.operator_states.begin(),
              missing_removal_result.operator_states.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    const auto missing_removal_root{
        missing_removal_result.RecomputeConsensusStateRoot(genesis)};
    BOOST_REQUIRE(missing_removal_root);
    missing_removal.consensus_state_root = *missing_removal_root;
    BOOST_REQUIRE(missing_removal.IsStructurallyValid());
    BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
        descending.GetHash(), missing_removal, /*fSync=*/true));
    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, descending.GetHash());
    PQRegistrySnapshot rejected;
    BOOST_CHECK(!manager.GetSnapshot(
        descending.GetHash(), registration.GetHash(), 1296, rejected,
        error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);

    auto no_op_update{original_ascending};
    const auto first_update{std::lower_bound(
        no_op_update.operator_states.begin(),
        no_op_update.operator_states.end(), first,
        [](const OperatorKeyState& state, const uint256& pro_tx_hash) {
            return state.pro_tx_hash < pro_tx_hash;
        })};
    BOOST_REQUIRE(first_update != no_op_update.operator_states.end());
    BOOST_REQUIRE(first_update->pro_tx_hash == first);
    *first_update = RequiredOperator(parent, first);
    auto no_op_result{ascending_snapshot};
    const auto no_op_first{std::lower_bound(
        no_op_result.operator_states.begin(),
        no_op_result.operator_states.end(), first,
        [](const OperatorKeyState& state, const uint256& pro_tx_hash) {
            return state.pro_tx_hash < pro_tx_hash;
        })};
    BOOST_REQUIRE(no_op_first != no_op_result.operator_states.end());
    BOOST_REQUIRE(no_op_first->pro_tx_hash == first);
    *no_op_first = RequiredOperator(parent, first);
    const auto no_op_root{
        no_op_result.RecomputeConsensusStateRoot(genesis)};
    BOOST_REQUIRE(no_op_root);
    no_op_update.consensus_state_root = *no_op_root;
    BOOST_REQUIRE(no_op_update.IsStructurallyValid());
    BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
        ascending.GetHash(), no_op_update, /*fSync=*/true));
    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, ascending.GetHash());
    BOOST_CHECK(!manager.GetSnapshot(
        ascending.GetHash(), registration.GetHash(), 1296, rejected,
        error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);
}

BOOST_AUTO_TEST_CASE(membership_reconciliation_is_checkpoint_only)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(551)};
    const uint256 first{NonNullHash(552)};
    const uint256 target{NonNullHash(553)};
    const uint256 removed{NonNullHash(554)};
    auto first_key{DeterministicKey(141)};
    auto target_key{DeterministicKey(142)};
    auto removed_key{DeterministicKey(143)};
    auto replacement_key{DeterministicKey(144)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    std::vector<uint256> all_operators{first, target, removed};
    std::sort(all_operators.begin(), all_operators.end());

    const auto registration{Block(
        NonNullHash(555), 551,
        {GlobalRegistration(
             genesis, first, first_key, owner_key,
             CommitmentAt(config, config.preparation_height, 1, 551), 552),
         GlobalRegistration(
             genesis, target, target_key, owner_key,
             CommitmentAt(config, config.preparation_height, 1, 552), 553),
         GlobalRegistration(
             genesis, removed, removed_key, owner_key,
             CommitmentAt(config, config.preparation_height, 1, 553),
             554)})};
    PQRegistryManager manager(MemoryDB(551), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, config.preparation_height,
        Members(genesis, all_operators, all_operators, owner_key_id), {},
        /*fJustCheck=*/false, error));

    std::vector<uint256> before_members{all_operators};
    std::vector<uint256> after_members{all_operators};
    std::vector<uint256> before_calls;
    std::vector<uint256> after_calls;
    const auto contains = [](const std::vector<uint256>& members,
                             const uint256& hash) {
        return std::binary_search(members.begin(), members.end(), hash);
    };
    PQRegistryCallbacks callbacks{
        [&](const uint256& hash) {
            before_calls.push_back(hash);
            return contains(before_members, hash);
        },
        [&](const uint256& hash) {
            after_calls.push_back(hash);
            return contains(after_members, hash);
        },
        {}};

    uint32_t block_id{555};
    int32_t height{config.preparation_height + 1};
    const uint32_t ordinary_id{block_id++};
    auto ordinary{Block(registration.GetHash(), ordinary_id,
                        {OrdinaryTransaction(ordinary_id)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        ordinary, height++, callbacks, {}, /*fJustCheck=*/false, error));
    BOOST_CHECK(before_calls.empty());
    BOOST_CHECK(after_calls.empty());

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        ordinary.GetHash(), registration.GetHash(), height - 1, parent,
        error));
    const auto rotation{GlobalRotation(
        genesis, target, RequiredOperator(parent, target).global_key,
        target_key, replacement_key,
        CommitmentAt(config, height, 2, 554), block_id++)};
    auto rotated{Block(ordinary.GetHash(), block_id++, {rotation})};
    BOOST_REQUIRE(manager.ProcessBlock(
        rotated, height++, callbacks, {}, /*fJustCheck=*/false, error));
    BOOST_REQUIRE_EQUAL(before_calls.size(), 1U);
    BOOST_REQUIRE_EQUAL(after_calls.size(), 1U);
    BOOST_CHECK(before_calls.front() == target);
    BOOST_CHECK(after_calls.front() == target);

    before_calls.clear();
    after_calls.clear();
    before_members = all_operators;
    after_members = all_operators;
    const auto removed_member{std::lower_bound(
        after_members.begin(), after_members.end(), removed)};
    BOOST_REQUIRE(removed_member != after_members.end());
    BOOST_REQUIRE(*removed_member == removed);
    after_members.erase(removed_member);
    const std::vector<uint256> removals{removed};
    const uint32_t removal_id{block_id++};
    auto removal{Block(rotated.GetHash(), removal_id,
                       {OrdinaryTransaction(removal_id)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        removal, height++, callbacks, removals,
        /*fJustCheck=*/false, error));
    BOOST_CHECK(before_calls.empty());
    BOOST_CHECK(after_calls.empty());

    before_members = after_members;
    uint256 cursor{removal.GetHash()};
    const int32_t checkpoint_height{
        config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL};
    while (height < checkpoint_height) {
        const uint32_t next_id{block_id++};
        auto next{Block(cursor, next_id, {OrdinaryTransaction(next_id)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            next, height++, callbacks, {}, /*fJustCheck=*/false, error));
        BOOST_CHECK(before_calls.empty());
        BOOST_CHECK(after_calls.empty());
        cursor = next.GetHash();
    }

    const uint32_t checkpoint_id{block_id++};
    auto checkpoint{Block(cursor, checkpoint_id,
                          {OrdinaryTransaction(checkpoint_id)})};
    const uint256 missing{before_members.front()};
    PQRegistryCallbacks mismatched{
        [&](const uint256& hash) {
            before_calls.push_back(hash);
            return hash != missing && contains(before_members, hash);
        },
        callbacks.dmn_exists_after,
        {}};
    BOOST_CHECK(!manager.ProcessBlock(
        checkpoint, checkpoint_height, mismatched, {},
        /*fJustCheck=*/true, error));
    BOOST_REQUIRE_EQUAL(before_calls.size(), 1U);
    BOOST_CHECK(before_calls.front() == missing);
    BOOST_CHECK(after_calls.empty());
    BOOST_CHECK(error.result == PQRegistryResult::PARENT_DMN_MISMATCH);
    BOOST_CHECK(error.pro_tx_hash == missing);
    BOOST_CHECK(!manager.SnapshotDatabase().ExistsCache(
        checkpoint.GetHash()));

    before_calls.clear();
    BOOST_REQUIRE(manager.ProcessBlock(
        checkpoint, checkpoint_height, callbacks, {},
        /*fJustCheck=*/false, error));
    BOOST_CHECK(before_calls == before_members);
    BOOST_CHECK(after_calls.empty());
}

BOOST_AUTO_TEST_CASE(checkpoint_retains_and_authenticates_exact_block_delta)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(651)};
    const uint256 updated{NonNullHash(652)};
    const uint256 removed{NonNullHash(653)};
    const uint256 added{NonNullHash(654)};
    auto updated_key{DeterministicKey(151)};
    auto removed_key{DeterministicKey(152)};
    auto replacement_key{DeterministicKey(153)};
    auto added_key{DeterministicKey(154)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    std::vector<uint256> all_members{updated, removed, added};
    std::sort(all_members.begin(), all_members.end());

    uint32_t block_id{70'000};
    const auto updated_initial{CommitmentAt(
        config, config.preparation_height, 1, block_id++)};
    const auto removed_initial{CommitmentAt(
        config, config.preparation_height, 1, block_id++)};
    const uint256 preparation_parent{NonNullHash(block_id++)};
    const uint32_t preparation_id{block_id++};
    const uint32_t updated_registration_id{block_id++};
    const uint32_t removed_registration_id{block_id++};
    const auto preparation{Block(
        preparation_parent, preparation_id,
        {GlobalRegistration(genesis, updated, updated_key, owner_key,
                            updated_initial, updated_registration_id),
         GlobalRegistration(genesis, removed, removed_key, owner_key,
                            removed_initial, removed_registration_id)})};
    PQRegistryManager manager(MemoryDB(651), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        preparation, config.preparation_height,
        Members(genesis, all_members, all_members, owner_key_id), {},
        /*fJustCheck=*/false, error));

    uint256 cursor{preparation.GetHash()};
    uint256 cursor_parent{preparation.hashPrevBlock};
    for (int32_t height{config.preparation_height + 1};
         height < config.preparation_height +
                      PQ_REGISTRY_CHECKPOINT_INTERVAL;
         ++height) {
        const auto ordinary{Block(
            cursor, block_id, {OrdinaryTransaction(block_id)})};
        ++block_id;
        BOOST_REQUIRE(manager.ProcessBlock(
            ordinary, height,
            Members(genesis, all_members, all_members, owner_key_id), {},
            /*fJustCheck=*/false, error));
        cursor_parent = cursor;
        cursor = ordinary.GetHash();
    }

    const int32_t checkpoint_height{
        config.preparation_height + PQ_REGISTRY_CHECKPOINT_INTERVAL};
    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        cursor, cursor_parent, checkpoint_height - 1, parent, error));
    const auto updated_next{CommitmentAt(
        config, checkpoint_height, 2, block_id++)};
    const auto added_initial{CommitmentAt(
        config, checkpoint_height, 1, block_id++)};
    const auto rotation{GlobalRotation(
        genesis, updated, RequiredOperator(parent, updated).global_key,
        updated_key, replacement_key, updated_next, block_id++)};
    const auto registration{GlobalRegistration(
        genesis, added, added_key, owner_key, added_initial, block_id++)};
    const auto checkpoint{Block(
        cursor, block_id++, {rotation, registration})};
    std::vector<uint256> resulting_members{updated, added};
    std::sort(resulting_members.begin(), resulting_members.end());
    const std::vector<uint256> removals{removed};
    BOOST_REQUIRE(manager.ProcessBlock(
        checkpoint, checkpoint_height,
        Members(genesis, all_members, resulting_members, owner_key_id),
        removals, /*fJustCheck=*/false, error));

    PQRegistrySnapshot expected;
    BOOST_REQUIRE(manager.GetSnapshot(
        checkpoint.GetHash(), cursor, checkpoint_height, expected, error));
    PQRegistryDiskSnapshot original;
    BOOST_REQUIRE(manager.SnapshotDatabase().ReadCache(
        checkpoint.GetHash(), original));
    BOOST_REQUIRE_EQUAL(original.is_checkpoint, 1U);
    BOOST_CHECK(original.removed_operators == removals);
    BOOST_REQUIRE_EQUAL(original.operator_states.size(), 2U);
    std::vector<uint256> delta_operators;
    for (const auto& state : original.operator_states) {
        delta_operators.push_back(state.pro_tx_hash);
    }
    BOOST_CHECK(delta_operators == resulting_members);
    BOOST_CHECK(original.checkpoint_operator_states ==
                expected.operator_states);
    BOOST_CHECK(original.tree_ids == expected.used_tree_ids);
    BOOST_CHECK(original.block_tree_ids == expected.block_tree_ids);
    BOOST_REQUIRE_EQUAL(original.block_tree_ids.size(), 2U);

    test::PQRegistryManagerTestAccess::ResetReconstructionStats(manager);
    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, checkpoint.GetHash());
    PQRegistrySnapshot reconstructed;
    BOOST_REQUIRE(manager.GetSnapshot(
        checkpoint.GetHash(), cursor, checkpoint_height, reconstructed,
        error));
    BOOST_CHECK(reconstructed == expected);
    BOOST_CHECK_LE(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .authenticated_records,
        static_cast<uint64_t>(PQ_REGISTRY_CHECKPOINT_INTERVAL + 1));

    const auto reject_tamper = [&](PQRegistryDiskSnapshot tampered) {
        BOOST_REQUIRE(tampered.IsStructurallyValid());
        BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
            checkpoint.GetHash(), tampered, /*fSync=*/true));
        test::PQRegistryManagerTestAccess::DropCachedSnapshot(
            manager, checkpoint.GetHash());
        PQRegistrySnapshot rejected;
        BOOST_CHECK(!manager.GetSnapshot(
            checkpoint.GetHash(), cursor, checkpoint_height, rejected,
            error));
        BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);
        BOOST_REQUIRE(manager.SnapshotDatabase().WriteThrough(
            checkpoint.GetHash(), original, /*fSync=*/true));
    };

    auto missing_operator_delta{original};
    missing_operator_delta.operator_states.erase(
        missing_operator_delta.operator_states.begin());
    reject_tamper(std::move(missing_operator_delta));

    auto missing_removal_delta{original};
    missing_removal_delta.removed_operators.clear();
    reject_tamper(std::move(missing_removal_delta));

    auto missing_tree_delta{original};
    missing_tree_delta.block_tree_ids.erase(
        missing_tree_delta.block_tree_ids.begin());
    reject_tamper(std::move(missing_tree_delta));

    test::PQRegistryManagerTestAccess::DropCachedSnapshot(
        manager, checkpoint.GetHash());
    BOOST_REQUIRE(manager.GetSnapshot(
        checkpoint.GetHash(), cursor, checkpoint_height, reconstructed,
        error));
    BOOST_CHECK(reconstructed == expected);
}

BOOST_AUTO_TEST_CASE(direct_validation_matches_single_transaction_block_checks)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(301)};
    const uint256 pro_tx_hash{NonNullHash(302)};
    const uint256 second_pro_tx_hash{NonNullHash(306)};
    auto key{DeterministicKey(121)};
    auto replacement_key{DeterministicKey(122)};
    auto duplicate_tree_key{DeterministicKey(123)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const auto first_tree{CommitmentAt(config, 1295, 1, 301)};
    PQRegistryManager manager(MemoryDB(301), genesis, config);
    PQRegistryError error;
    const auto registration{Block(
        NonNullHash(303), 301,
        {GlobalRegistration(genesis, pro_tx_hash, key, owner_key,
                            first_tree, 302)})};
    const auto callbacks{Members(
        genesis, {pro_tx_hash, second_pro_tx_hash},
        {pro_tx_hash, second_pro_tx_hash}, owner_key_id)};
    BOOST_REQUIRE(manager.ProcessBlock(registration, 1295, callbacks, {},
                                       /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    const GlobalKeyRecord current{OnlyOperator(parent).global_key};
    const auto next_tree{CommitmentAt(config, 1296, 2, 303)};
    const auto valid{GlobalRotation(
        genesis, pro_tx_hash, current, key, replacement_key, next_tree,
        303)};

    uint32_t block_id{304};
    const auto check_parity =
        [&](const CTransactionRef& candidate, bool expected_ok,
            PQRegistryResult expected_result) {
            PQRegistryError direct_error;
            const bool direct_ok{manager.ValidateTransaction(
                *candidate, registration.GetHash(), 1296, callbacks,
                /*check_sigs=*/true, direct_error)};
            PQRegistryError block_error;
            const auto candidate_block{Block(
                registration.GetHash(), block_id++, {candidate})};
            const bool block_ok{manager.ProcessBlock(
                candidate_block, 1296, callbacks, {},
                /*fJustCheck=*/true, block_error)};
            BOOST_CHECK_EQUAL(direct_ok, expected_ok);
            BOOST_CHECK_EQUAL(block_ok, expected_ok);
            BOOST_CHECK(direct_error.result == expected_result);
            BOOST_CHECK(direct_error == block_error);
        };

    check_parity(valid, /*expected_ok=*/true, PQRegistryResult::OK);
    check_parity(CorruptAuthorization(valid), /*expected_ok=*/false,
                 PQRegistryResult::OPERATOR_STATE_TRANSITION_FAILED);

    CMutableTransaction changed_inputs{*valid};
    changed_inputs.vin[0].prevout = COutPoint{NonNullHash(304), 304};
    check_parity(MakeTransactionRef(std::move(changed_inputs)),
                 /*expected_ok=*/false,
                 PQRegistryResult::TRANSACTION_INPUTS_HASH_MISMATCH);

    CMutableTransaction noncanonical{*valid};
    const int payload_output{GetSyscoinDataOutput(noncanonical)};
    BOOST_REQUIRE(payload_output >= 0);
    noncanonical.vout[payload_output].scriptPubKey << OP_TRUE;
    check_parity(MakeTransactionRef(std::move(noncanonical)),
                 /*expected_ok=*/false,
                 PQRegistryResult::INVALID_GLOBAL_KEY_PAYLOAD);

    auto reused_tree{CommitmentAt(config, 1296, 1, 305)};
    reused_tree.tree_id = first_tree.tree_id;
    BOOST_REQUIRE(reused_tree.IsStructurallyValid());
    check_parity(GlobalRegistration(
                     genesis, second_pro_tx_hash, duplicate_tree_key,
                     owner_key, reused_tree, 305),
                 /*expected_ok=*/false,
                 PQRegistryResult::DUPLICATE_CHILD_TREE_ID);
}

BOOST_AUTO_TEST_CASE(direct_validation_stops_at_target_membership_failure)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(311)};
    const uint256 pro_tx_hash{NonNullHash(312)};
    const uint256 parent{NonNullHash(313)};
    auto key{DeterministicKey(124)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const auto registration{GlobalRegistration(
        genesis, pro_tx_hash, key, owner_key,
        CommitmentAt(config, 1295, 1, 311), 311)};
    PQRegistryManager manager(MemoryDB(311), genesis, config);
    PQRegistryError error;
    std::string calls;

    PQRegistryCallbacks callbacks{
        [&](const uint256&) -> bool {
            calls += 'b';
            throw std::runtime_error{"before"};
        },
        [&](const uint256&) {
            calls += 'a';
            return true;
        },
        {}};
    BOOST_CHECK(!manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(calls, "b");
    BOOST_CHECK(error.result == PQRegistryResult::CALLBACK_FAILED);
    BOOST_CHECK_EQUAL(error.transaction_index, 0U);
    BOOST_CHECK(error.pro_tx_hash == pro_tx_hash);

    calls.clear();
    callbacks.dmn_exists_before = [&](const uint256&) {
        calls += 'b';
        return false;
    };
    BOOST_CHECK(!manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(calls, "b");
    BOOST_CHECK(error.result == PQRegistryResult::DMN_MISSING_AT_PARENT);

    calls.clear();
    callbacks.dmn_exists_before = [&](const uint256&) {
        calls += 'b';
        return true;
    };
    callbacks.dmn_exists_after = [&](const uint256&) -> bool {
        calls += 'a';
        throw std::runtime_error{"after"};
    };
    BOOST_CHECK(!manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(calls, "ba");
    BOOST_CHECK(error.result == PQRegistryResult::CALLBACK_FAILED);

    calls.clear();
    callbacks.dmn_exists_after = [&](const uint256&) {
        calls += 'a';
        return false;
    };
    BOOST_CHECK(!manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(calls, "ba");
    BOOST_CHECK(error.result == PQRegistryResult::DMN_REMOVED_IN_BLOCK);

    calls.clear();
    callbacks.dmn_exists_after = [&](const uint256&) {
        calls += 'a';
        return true;
    };
    BOOST_REQUIRE(manager.ValidateTransaction(
        *registration, parent, 1295, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK_EQUAL(calls, "ba");

    calls.clear();
    BOOST_CHECK(!manager.ValidateTransaction(
        *registration, NonNullHash(314), 1296, callbacks,
        /*check_sigs=*/false, error));
    BOOST_CHECK(calls.empty());
    BOOST_CHECK(error.result == PQRegistryResult::MISSING_PARENT_SNAPSHOT);
}

BOOST_AUTO_TEST_CASE(direct_validation_does_not_visit_unrelated_operators)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(321)};
    const uint256 first{NonNullHash(322)};
    const uint256 target{NonNullHash(323)};
    const uint256 third{NonNullHash(324)};
    auto first_key{DeterministicKey(125)};
    auto target_key{DeterministicKey(126)};
    auto third_key{DeterministicKey(127)};
    auto replacement_key{DeterministicKey(128)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    const std::vector<uint256> operators{first, target, third};
    const auto registration{Block(
        NonNullHash(325), 321,
        {GlobalRegistration(
             genesis, first, first_key, owner_key,
             CommitmentAt(config, 1295, 1, 321), 322),
         GlobalRegistration(
             genesis, target, target_key, owner_key,
             CommitmentAt(config, 1295, 1, 322), 323),
         GlobalRegistration(
             genesis, third, third_key, owner_key,
             CommitmentAt(config, 1295, 1, 323), 324)})};
    PQRegistryManager manager(MemoryDB(321), genesis, config);
    PQRegistryError error;
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295,
        Members(genesis, operators, operators, owner_key_id), {},
        /*fJustCheck=*/false, error));

    PQRegistrySnapshot parent;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295, parent,
        error));
    const auto target_state{std::find_if(
        parent.operator_states.begin(), parent.operator_states.end(),
        [&](const OperatorKeyState& state) {
            return state.pro_tx_hash == target;
        })};
    BOOST_REQUIRE(target_state != parent.operator_states.end());
    const auto rotation{GlobalRotation(
        genesis, target, target_state->global_key, target_key,
        replacement_key, CommitmentAt(config, 1296, 2, 324), 325)};

    std::vector<uint256> before_calls;
    std::vector<uint256> after_calls;
    PQRegistryCallbacks direct_callbacks{
        [&](const uint256& hash) {
            before_calls.push_back(hash);
            if (hash != target) {
                throw std::runtime_error{"unrelated before lookup"};
            }
            return true;
        },
        [&](const uint256& hash) {
            after_calls.push_back(hash);
            if (hash != target) {
                throw std::runtime_error{"unrelated after lookup"};
            }
            return true;
        },
        {}};
    BOOST_REQUIRE(manager.ValidateTransaction(
        *rotation, registration.GetHash(), 1296, direct_callbacks,
        /*check_sigs=*/false, error));
    // SYSCOIN: The accepted-parent integrity check and the candidate-local
    // membership check both touch the target, but neither may walk unrelated
    // registry operators.
    BOOST_REQUIRE_EQUAL(before_calls.size(), 2U);
    BOOST_REQUIRE_EQUAL(after_calls.size(), 1U);
    BOOST_CHECK(before_calls.front() == target);
    BOOST_CHECK(before_calls.back() == target);
    BOOST_CHECK(after_calls.front() == target);
}

BOOST_AUTO_TEST_CASE(direct_validation_rejects_key_retained_after_revocation)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(331)};
    const uint256 first{NonNullHash(332)};
    const uint256 second{NonNullHash(333)};
    auto retained_key{DeterministicKey(129)};
    CKey owner_key;
    owner_key.MakeNewKey(/*fCompressed=*/true);
    const CKeyID owner_key_id{owner_key.GetPubKey().GetID()};
    PQRegistryManager manager(MemoryDB(331), genesis, config);
    PQRegistryError error;
    const auto registration{Block(
        NonNullHash(334), 331,
        {GlobalRegistration(
            genesis, first, retained_key, owner_key,
            CommitmentAt(config, 1295, 1, 331), 332)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        registration, 1295,
        Member(genesis, first, owner_key_id), {},
        /*fJustCheck=*/false, error));

    PQRegistrySnapshot registered;
    BOOST_REQUIRE(manager.GetSnapshot(
        registration.GetHash(), registration.hashPrevBlock, 1295,
        registered, error));
    const auto revoke{Block(
        registration.GetHash(), 333,
        {ProviderRevocation(
            genesis, first, OnlyOperator(registered).global_key,
            retained_key, 334)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        revoke, 1296, Member(genesis, first, owner_key_id), {},
        /*fJustCheck=*/false, error));

    PQRegistryReadView revoked_view;
    BOOST_REQUIRE(manager.GetReadView(
        revoke.GetHash(), registration.GetHash(), 1296, revoked_view,
        error));
    const auto retained_owner{revoked_view.FindRetainedGlobalKeyOwner(
        OnlyOperator(registered).global_key.public_key)};
    BOOST_REQUIRE(retained_owner);
    BOOST_CHECK(*retained_owner == first);
    BOOST_CHECK(!revoked_view.FindActiveOperatorByGlobalKey(
        OnlyOperator(registered).global_key.public_key));

    const auto collision{GlobalRegistration(
        genesis, second, retained_key, owner_key,
        CommitmentAt(config, 1297, 1, 332), 335)};
    auto callbacks{Members(genesis, {first, second}, {first, second},
                           owner_key_id)};
    std::size_t owner_calls{0};
    const auto verify_owner{callbacks.verify_initial_owner_authorization};
    callbacks.verify_initial_owner_authorization =
        [&](const GlobalKeyTxPayload& payload, const uint256& digest) {
            ++owner_calls;
            return verify_owner(payload, digest);
        };
    PQRegistryError direct_error;
    BOOST_CHECK(!manager.ValidateTransaction(
        *collision, revoke.GetHash(), 1297, callbacks,
        /*check_sigs=*/true, direct_error));
    BOOST_CHECK(direct_error.result ==
                PQRegistryResult::DUPLICATE_GLOBAL_KEY);
    BOOST_CHECK_EQUAL(direct_error.transaction_index, 0U);
    BOOST_CHECK(direct_error.pro_tx_hash == second);
    BOOST_CHECK_EQUAL(owner_calls, 0U);

    PQRegistryError block_error;
    const auto collision_block{Block(
        revoke.GetHash(), 335, {collision})};
    BOOST_CHECK(!manager.ProcessBlock(
        collision_block, 1297, callbacks, {},
        /*fJustCheck=*/true, block_error));
    BOOST_CHECK(direct_error == block_error);
    BOOST_CHECK_EQUAL(owner_calls, 0U);
}

BOOST_AUTO_TEST_CASE(gc_rooted_floor_is_branch_bound_and_monotonic)
{
    EmptyRootedGCHistory history{80'100};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto initial_context{
        history.Context(history.initial_checkpoint_height)};
    const auto later_context{
        history.Context(history.second_checkpoint_height)};
    const auto authorization{FloorAuthorization(
        history.second_checkpoint_height + 100, 80'101)};
    const uint256 cursor_one{NonNullHash(1)};
    const uint256 cursor_two{NonNullHash(2)};
    const auto& floor_identity{
        history.Identity(history.initial_checkpoint_height)};
    const auto& floor_parent{
        history.Identity(history.initial_checkpoint_height - 1)};
    const auto& floor_grandparent{
        history.Identity(history.initial_checkpoint_height - 2)};
    const CBlock competing_floor{Block(
        floor_parent.block_hash, 80'105,
        {OrdinaryTransaction(80'105)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        competing_floor, history.initial_checkpoint_height,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        /*fJustCheck=*/false, error));

    evo::PQRegistryGCClosure first;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/1, cursor_one, initial_context, nullptr,
        first, error));
    BOOST_REQUIRE(manager.InstallGCFloor(
        FloorComponent(first), authorization, error, initial_context));
    const auto first_stats{
        test::PQRegistryManagerTestAccess::Stats(manager)};
    BOOST_CHECK_EQUAL(first_stats.gc_floor_revision, 1U);

    PQRegistrySnapshot snapshot;
    BOOST_CHECK(!manager.GetSnapshot(
        floor_parent.block_hash, floor_grandparent.block_hash,
        floor_parent.height, snapshot, error));
    BOOST_CHECK(error.result == PQRegistryResult::HISTORY_PRUNED);
    BOOST_CHECK(!manager.GetSnapshot(
        competing_floor.GetHash(), floor_parent.block_hash,
        history.initial_checkpoint_height, snapshot, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);
    BOOST_REQUIRE(manager.GetSnapshot(
        floor_identity.block_hash, floor_parent.block_hash,
        floor_identity.height, snapshot, error));
    const auto& floor_child{
        history.Identity(history.initial_checkpoint_height + 1)};
    BOOST_REQUIRE(manager.GetSnapshot(
        floor_child.block_hash, floor_identity.block_hash,
        floor_child.height, snapshot, error));

    const CBlock below_floor_candidate{Block(
        floor_grandparent.block_hash, 80'106,
        {OrdinaryTransaction(80'106)})};
    PQRegistryPreparedBlock boundary_prepared;
    BOOST_CHECK(!manager.PrepareBlock(
        below_floor_candidate, floor_parent.height,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        boundary_prepared, error));
    BOOST_CHECK(error.result == PQRegistryResult::HISTORY_PRUNED);
    const std::vector<uint256> no_operators;
    PQRegistryMempoolView mempool_view;
    BOOST_CHECK(!manager.GetMempoolView(
        floor_parent.block_hash, floor_parent.height,
        no_operators, mempool_view, error));
    BOOST_CHECK(error.result == PQRegistryResult::HISTORY_PRUNED);
    BOOST_CHECK(!manager.PreflightUndoBlock(
        floor_identity.block_hash, floor_parent.block_hash,
        floor_identity.height, error));
    BOOST_CHECK(error.result == PQRegistryResult::HISTORY_PRUNED);

    evo::PQRegistryGCClosure cursor_progress;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/2, cursor_two, initial_context, &first,
        cursor_progress, error));
    BOOST_CHECK(cursor_progress.lineage_base_commitment ==
                first.lineage_base_commitment);
    BOOST_CHECK(cursor_progress.rooted_lineage_commitment ==
                first.rooted_lineage_commitment);
    BOOST_REQUIRE(manager.InstallGCFloor(
        FloorComponent(cursor_progress), authorization, error,
        initial_context));
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        first_stats.gc_floor_revision);

    auto mutated_rooted{cursor_progress};
    mutated_rooted.generation = 3;
    mutated_rooted.rooted_lineage_commitment = NonNullHash(80'102);
    mutated_rooted.scan_after_key.reset();
    mutated_rooted.scan_complete = evo::PQRegistryGCClosure::COMPLETE;
    BOOST_CHECK(!manager.InstallGCFloor(
        FloorComponent(mutated_rooted), authorization, error,
        initial_context));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        first_stats.gc_floor_revision);

    auto mutated_base{cursor_progress};
    mutated_base.generation = 3;
    mutated_base.lineage_base_commitment = NonNullHash(80'103);
    mutated_base.scan_after_key.reset();
    mutated_base.scan_complete = evo::PQRegistryGCClosure::COMPLETE;
    BOOST_CHECK(!manager.InstallGCFloor(
        FloorComponent(mutated_base), authorization, error,
        initial_context));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);

    evo::PQRegistryGCClosure complete;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/3, std::nullopt, initial_context,
        &cursor_progress, complete, error));
    BOOST_REQUIRE(manager.InstallGCFloor(
        FloorComponent(complete), authorization, error,
        initial_context));

    evo::PQRegistryGCClosure later;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/4, NonNullHash(3), later_context, &complete,
        later, error));
    BOOST_CHECK(later.lineage_base_commitment ==
                complete.rooted_lineage_commitment);
    BOOST_REQUIRE(manager.InstallGCFloor(
        FloorComponent(later), authorization, error, later_context));
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        first_stats.gc_floor_revision + 1);

    evo::PQRegistryGCClosure later_complete;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/5, std::nullopt, later_context, &later,
        later_complete, error));
    BOOST_REQUIRE(manager.InstallGCFloor(
        FloorComponent(later_complete), authorization, error,
        later_context));

    // Once C0 roots the next bounded segment, transient A+1..C0-1 records
    // are no longer part of either retained witness.
    for (int32_t height{history.anchor_height + 1};
         height < history.initial_checkpoint_height; ++height) {
        BOOST_REQUIRE(
            test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
                manager, history.Identity(height).block_hash));
    }
    evo::AuxiliaryHistoryGCWatermark restarted;
    restarted.sequence = 5;
    restarted.configuration_id = history.configuration_id;
    restarted.authorization = authorization;
    restarted.frontier.pq_registry = FloorComponent(later_complete);
    restarted.completed_intent_id = NonNullHash(80'107);
    restarted.watermark_id = NonNullHash(80'108);
    BOOST_REQUIRE(manager.InstallEffectiveGCFloor(
        {restarted, std::nullopt}, error, later_context));

    evo::PQRegistryGCClosure regressed;
    BOOST_CHECK(!manager.BuildGCFloorClosure(
        /*generation=*/6, NonNullHash(4), initial_context,
        &later_complete,
        regressed, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);

    evo::PQRegistryGCClosure skipped;
    BOOST_CHECK(!manager.BuildGCFloorClosure(
        /*generation=*/1, NonNullHash(4), later_context, nullptr,
        skipped, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);
    BOOST_REQUIRE(manager.VerifyGCLegacyIsland(
        later_context.legacy_island, error));
}

BOOST_AUTO_TEST_CASE(gc_rooted_floor_handles_legacy_anchor_boundaries)
{
    constexpr std::array<int32_t, 3> anchor_offsets{
        0,
        PQ_REGISTRY_CHECKPOINT_INTERVAL - 1,
        PQ_REGISTRY_CHECKPOINT_INTERVAL,
    };
    uint32_t fixture_id{80'150};
    for (const int32_t anchor_offset : anchor_offsets) {
        EmptyRootedGCHistory history{fixture_id, anchor_offset};
        fixture_id += 10;
        PQRegistryError error;
        const auto context{
            history.Context(history.initial_checkpoint_height)};
        BOOST_REQUIRE(history.manager->VerifyGCLegacyIsland(
            context.legacy_island, error));

        evo::PQRegistryGCClosure closure;
        BOOST_REQUIRE(history.manager->BuildGCFloorClosure(
            /*generation=*/1, std::nullopt, context, nullptr,
            closure, error));
        BOOST_CHECK(closure.checkpoint ==
                    history.Identity(history.initial_checkpoint_height));
        BOOST_CHECK_EQUAL(
            context.legacy_island.size(),
            static_cast<std::size_t>(
                history.anchor_height - history.island_base_height + 1));
        BOOST_CHECK_EQUAL(
            context.rooted_segment.size(),
            static_cast<std::size_t>(
                history.initial_checkpoint_height -
                history.anchor_height + 1));
    }
}

BOOST_AUTO_TEST_CASE(gc_rooted_floor_rejects_wrong_or_damaged_paths)
{
    EmptyRootedGCHistory history{80'200};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{history.Context(history.initial_checkpoint_height)};
    evo::PQRegistryGCClosure canonical;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/1, NonNullHash(1), context, nullptr,
        canonical, error));

    auto wrong_anchor{context};
    wrong_anchor.legacy_island.back().block_hash = NonNullHash(80'201);
    BOOST_CHECK(!manager.InstallGCFloor(
        FloorComponent(canonical),
        FloorAuthorization(history.second_checkpoint_height + 10, 80'202),
        error, wrong_anchor));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);

    auto wrong_base{context};
    wrong_base.legacy_island.front().block_hash = NonNullHash(80'204);
    BOOST_CHECK(!manager.InstallGCFloor(
        FloorComponent(canonical),
        FloorAuthorization(history.second_checkpoint_height + 10, 80'205),
        error, wrong_base));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);

    auto mislinked{context};
    std::swap(mislinked.rooted_segment[1].block_hash,
              mislinked.rooted_segment[2].block_hash);
    BOOST_CHECK(!manager.InstallGCFloor(
        FloorComponent(canonical),
        FloorAuthorization(history.second_checkpoint_height + 10, 80'203),
        error, mislinked));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);

    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::AppendTrailingDiskByte(
        manager, context.legacy_island.front().block_hash));
    BOOST_CHECK(!manager.VerifyGCLegacyIsland(
        context.legacy_island, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        0U);

    EmptyRootedGCHistory missing{80'210};
    const auto missing_context{
        missing.Context(missing.initial_checkpoint_height)};
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
        *missing.manager,
        missing_context.legacy_island.front().block_hash));
    BOOST_CHECK(!missing.manager->VerifyGCLegacyIsland(
        missing_context.legacy_island, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);
}

BOOST_AUTO_TEST_CASE(gc_rooted_floor_restart_requires_retained_segment_base)
{
    EmptyRootedGCHistory history{80'250};
    PQRegistryError error;
    const auto initial_context{
        history.Context(history.initial_checkpoint_height)};
    const auto later_context{
        history.Context(history.second_checkpoint_height)};
    evo::PQRegistryGCClosure initial;
    BOOST_REQUIRE(history.manager->BuildGCFloorClosure(
        /*generation=*/1, std::nullopt, initial_context, nullptr,
        initial, error));
    evo::PQRegistryGCClosure later;
    BOOST_REQUIRE(history.manager->BuildGCFloorClosure(
        /*generation=*/2, std::nullopt, later_context, &initial,
        later, error));

    const auto& retained_base{later_context.rooted_segment.front()};
    BOOST_REQUIRE(retained_base == initial.checkpoint);
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
        *history.manager, retained_base.block_hash));

    evo::AuxiliaryHistoryGCWatermark watermark;
    watermark.sequence = 2;
    watermark.configuration_id = history.configuration_id;
    watermark.authorization = FloorAuthorization(
        history.second_checkpoint_height + 10, 80'251);
    watermark.frontier.pq_registry = FloorComponent(later);
    watermark.completed_intent_id = NonNullHash(80'252);
    watermark.watermark_id = NonNullHash(80'253);
    BOOST_CHECK(!history.manager->InstallEffectiveGCFloor(
        {watermark, std::nullopt}, error, later_context));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(*history.manager)
            .gc_floor_revision,
        0U);
}

BOOST_AUTO_TEST_CASE(gc_rooted_floor_requires_configuration_and_exact_record)
{
    const auto config{FastConfig()};
    const uint256 genesis{NonNullHash(80'300)};
    PQRegistryManager rootless{MemoryDB(80'300), genesis, config};
    PQRegistryError error;
    evo::PQRegistryGCClosure closure;
    PQRegistryGCAuthenticationContext empty_context;
    BOOST_CHECK(!rootless.BuildGCFloorClosure(
        /*generation=*/1, NonNullHash(1), empty_context, nullptr,
        closure, error));
    BOOST_CHECK(error.result == PQRegistryResult::INVALID_CONFIGURATION);
    BOOST_REQUIRE(rootless.InstallEffectiveGCFloor({}, error));

    EmptyRootedGCHistory exact{80'310};
    auto context{exact.Context(exact.initial_checkpoint_height)};
    BOOST_REQUIRE(exact.manager->BuildGCFloorClosure(
        /*generation=*/1, NonNullHash(1), context, nullptr,
        closure, error));
    BOOST_CHECK(!rootless.InstallGCFloor(
        FloorComponent(closure),
        FloorAuthorization(exact.second_checkpoint_height + 10, 80'312),
        error, context));
    BOOST_CHECK(error.result == PQRegistryResult::INVALID_CONFIGURATION);
    evo::AuxiliaryHistoryGCWatermark nonempty;
    nonempty.sequence = 1;
    nonempty.configuration_id = NonNullHash(80'313);
    nonempty.authorization =
        FloorAuthorization(exact.second_checkpoint_height + 10, 80'314);
    nonempty.frontier.pq_registry = FloorComponent(closure);
    nonempty.completed_intent_id = NonNullHash(80'315);
    nonempty.watermark_id = NonNullHash(80'316);
    BOOST_CHECK(!rootless.InstallEffectiveGCFloor(
        {nonempty, std::nullopt}, error, context));
    BOOST_CHECK(error.result == PQRegistryResult::INVALID_CONFIGURATION);
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
        *exact.manager, context.rooted_segment.back().block_hash));
    BOOST_CHECK(!exact.manager->InstallGCFloor(
        FloorComponent(closure),
        FloorAuthorization(exact.second_checkpoint_height + 10, 80'311),
        error, context));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_NOT_FOUND);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(*exact.manager)
            .gc_floor_revision,
        0U);
}

BOOST_AUTO_TEST_CASE(gc_effective_floor_protects_rooted_exact_keys)
{
    EmptyRootedGCHistory history{80'400};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{history.Context(history.initial_checkpoint_height)};
    evo::PQRegistryGCClosure closure;
    uint256 scan_max;
    std::fill(scan_max.begin(), scan_max.end(), 0xff);
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/1, scan_max, context, nullptr,
        closure, error));
    const auto component{FloorComponent(closure)};
    const auto authorization{FloorAuthorization(
        history.second_checkpoint_height + 10, 80'401)};

    evo::PQRegistryGCEraseManifest decoded;
    decoded.target_component_hash =
        *evo::GetAuxiliaryHistoryGCComponentHash(component);
    decoded.scan_through = closure.scan_after_key;
    decoded.candidates.push_back({
        context.legacy_island.front().block_hash,
        context.legacy_island.front().height,
        NonNullHash(80'402)});
    const auto encoded{evo::EncodePQRegistryGCEraseManifest(decoded)};
    BOOST_REQUIRE(encoded);
    evo::AuxiliaryHistoryGCIntent intent;
    intent.sequence = 1;
    intent.configuration_id = history.configuration_id;
    intent.target.authorization = authorization;
    intent.target.frontier.pq_registry = component;
    intent.target.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
        evo::PQRegistryGCEraseManifest::VERSION, *encoded};
    intent.intent_id = NonNullHash(80'403);
    BOOST_CHECK(!manager.InstallEffectiveGCFloor(
        {std::nullopt, intent}, error, context));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        0U);

    // A key at the same height but on another branch is not part of the
    // authenticated island and therefore remains a valid erase candidate.
    const CBlock side_q{Block(
        history.blocks.front().hashPrevBlock, 80'404,
        {OrdinaryTransaction(80'404)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        side_q, history.config.preparation_height,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        /*fJustCheck=*/false, error));
    PQRegistryDiskSnapshot side_disk;
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, side_q.GetHash(), side_disk));
    decoded.candidates.front().key = side_q.GetHash();
    decoded.candidates.front().exact_record_hash =
        ::SerializeHash(side_disk);
    const auto side_encoded{
        evo::EncodePQRegistryGCEraseManifest(decoded)};
    BOOST_REQUIRE(side_encoded);
    intent.target.pq_erase_manifest->payload = *side_encoded;
    BOOST_REQUIRE(manager.InstallEffectiveGCFloor(
        {std::nullopt, intent}, error, context));
    BOOST_CHECK_EQUAL(
        test::PQRegistryManagerTestAccess::Stats(manager)
            .gc_floor_revision,
        1U);
}

BOOST_AUTO_TEST_CASE(gc_erase_batch_advances_physical_scan_cursor)
{
    EmptyRootedGCHistory history{80'500};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent first;
    evo::PQRegistryGCEraseManifest first_manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt, /*max_scanned_records=*/1,
        /*max_candidates=*/1,
        first, first_manifest, error));
    const auto first_closure{
        evo::DecodePQRegistryGCClosure(first.closure)};
    BOOST_REQUIRE(first_closure);
    BOOST_CHECK_EQUAL(first_closure->generation, 1U);
    BOOST_CHECK_EQUAL(first_closure->scan_complete,
                      evo::PQRegistryGCClosure::SCANNING);
    BOOST_CHECK(!first_manifest.from_cursor);
    BOOST_REQUIRE(first_manifest.scan_through);
    BOOST_CHECK(first_closure->scan_after_key ==
                first_manifest.scan_through);
    BOOST_CHECK_EQUAL(first_manifest.reached_eof, 0U);
    BOOST_CHECK_LE(first_manifest.candidates.size(), 1U);

    evo::AuxiliaryHistoryGCComponent second;
    evo::PQRegistryGCEraseManifest second_manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, first, /*max_scanned_records=*/1,
        /*max_candidates=*/1,
        second, second_manifest, error));
    const auto second_closure{
        evo::DecodePQRegistryGCClosure(second.closure)};
    BOOST_REQUIRE(second_closure);
    BOOST_CHECK_EQUAL(second_closure->generation, 2U);
    BOOST_CHECK(second_manifest.from_cursor ==
                first_manifest.scan_through);
    BOOST_REQUIRE(second_manifest.scan_through);
    BOOST_CHECK(*first_manifest.scan_through <
                *second_manifest.scan_through);
    BOOST_CHECK(second_closure->scan_after_key ==
                second_manifest.scan_through);
    BOOST_CHECK_LE(second_manifest.candidates.size(), 1U);
}

BOOST_AUTO_TEST_CASE(gc_erase_batch_caps_nonerasable_scan_work)
{
    EmptyRootedGCHistory history{80'525};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    const auto& checkpoint{
        history.Identity(history.initial_checkpoint_height)};
    for (uint32_t offset{0};
         offset < evo::PQRegistryGCEraseManifest::MAX_CANDIDATES;
         ++offset) {
        const uint32_t tag{82'000 + offset};
        const CBlock above_floor{Block(
            checkpoint.block_hash, tag,
            {OrdinaryTransaction(tag)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            above_floor, checkpoint.height + 1,
            Members(history.genesis, {}, {}, CKeyID{}), {},
            /*fJustCheck=*/false, error));
    }
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        /*max_scanned_records=*/4096,
        /*max_candidates=*/256,
        target, manifest, error));
    const auto closure{evo::DecodePQRegistryGCClosure(target.closure)};
    BOOST_REQUIRE(closure);
    BOOST_CHECK_EQUAL(closure->scan_complete,
                      evo::PQRegistryGCClosure::SCANNING);
    BOOST_CHECK_EQUAL(manifest.reached_eof, 0U);
    BOOST_CHECK(manifest.candidates.empty());
    BOOST_REQUIRE(manifest.scan_through);
    BOOST_CHECK(closure->scan_after_key == manifest.scan_through);
}

BOOST_AUTO_TEST_CASE(gc_erase_batch_protects_paths_and_is_idempotent)
{
    EmptyRootedGCHistory history{80'550};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    const CBlock side_q{Block(
        history.blocks.front().hashPrevBlock, 80'551,
        {OrdinaryTransaction(80'551)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        side_q, history.config.preparation_height,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        /*fJustCheck=*/false, error));
    const CBlock side_c{Block(
        history.Identity(history.initial_checkpoint_height - 1).block_hash,
        80'552, {OrdinaryTransaction(80'552)})};
    BOOST_REQUIRE(manager.ProcessBlock(
        side_c, history.initial_checkpoint_height,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        /*fJustCheck=*/false, error));
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        target, manifest, error));
    const auto closure{evo::DecodePQRegistryGCClosure(target.closure)};
    BOOST_REQUIRE(closure);
    BOOST_CHECK_EQUAL(closure->scan_complete,
                      evo::PQRegistryGCClosure::COMPLETE);
    BOOST_CHECK_EQUAL(manifest.reached_eof, 1U);
    BOOST_REQUIRE_EQUAL(manifest.candidates.size(), 2U);
    const auto find_candidate = [&](const uint256& key) {
        return std::find_if(
            manifest.candidates.begin(), manifest.candidates.end(),
            [&](const auto& candidate) { return candidate.key == key; });
    };
    const auto side_q_candidate{find_candidate(side_q.GetHash())};
    BOOST_REQUIRE(side_q_candidate != manifest.candidates.end());
    BOOST_CHECK_EQUAL(side_q_candidate->height,
                      history.config.preparation_height);
    const auto side_c_candidate{find_candidate(side_c.GetHash())};
    BOOST_REQUIRE(side_c_candidate != manifest.candidates.end());
    BOOST_CHECK_EQUAL(side_c_candidate->height,
                      history.initial_checkpoint_height);

    const auto& protected_q{context.legacy_island.front()};
    PQRegistryDiskSnapshot protected_disk;
    BOOST_REQUIRE(
        test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
            manager, protected_q.block_hash, protected_disk));
    BOOST_REQUIRE(manager.InstallGCFloor(
        target,
        FloorAuthorization(history.second_checkpoint_height + 10,
                           80'553),
        error, context));
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));

    PQRegistryDiskSnapshot erased;
    BOOST_CHECK(!test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, side_q.GetHash(), erased));
    BOOST_CHECK(!test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, side_c.GetHash(), erased));
    BOOST_REQUIRE(
        test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
            manager, protected_q.block_hash, protected_disk));
    const auto& protected_c{context.rooted_segment.back()};
    BOOST_REQUIRE(
        test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
            manager, protected_c.block_hash, protected_disk));
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
}

BOOST_AUTO_TEST_CASE(gc_erase_manifest_resumes_only_over_missing_prefix)
{
    EmptyRootedGCHistory history{80'600};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    for (uint32_t tag{80'601}; tag <= 80'603; ++tag) {
        const CBlock side{Block(
            history.blocks.front().hashPrevBlock, tag,
            {OrdinaryTransaction(tag)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            side, history.config.preparation_height,
            Members(history.genesis, {}, {}, CKeyID{}), {},
            /*fJustCheck=*/false, error));
    }
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        target, manifest, error));
    BOOST_REQUIRE_EQUAL(manifest.candidates.size(), 3U);
    BOOST_REQUIRE(manager.InstallGCFloor(
        target,
        FloorAuthorization(history.second_checkpoint_height + 10,
                           80'604),
        error, context));

    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
        manager, manifest.candidates.front().key));
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
    for (const auto& candidate : manifest.candidates) {
        PQRegistryDiskSnapshot disk;
        BOOST_CHECK(
            !test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
                manager, candidate.key, disk));
    }
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
}

BOOST_AUTO_TEST_CASE(gc_erase_batch_caps_dense_candidates_and_retries)
{
    EmptyRootedGCHistory history{80'625};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    std::vector<uint256> side_hashes;
    side_hashes.reserve(257);
    for (uint32_t offset{0}; offset < 257; ++offset) {
        const uint32_t tag{81'000 + offset};
        const CBlock side{Block(
            history.blocks.front().hashPrevBlock, tag,
            {OrdinaryTransaction(tag)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            side, history.config.preparation_height,
            Members(history.genesis, {}, {}, CKeyID{}), {},
            /*fJustCheck=*/false, error));
        side_hashes.push_back(side.GetHash());
    }
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        target, manifest, error));
    BOOST_REQUIRE_EQUAL(manifest.candidates.size(), 256U);
    const auto closure{evo::DecodePQRegistryGCClosure(target.closure)};
    BOOST_REQUIRE(closure);
    BOOST_CHECK_EQUAL(closure->scan_complete,
                      evo::PQRegistryGCClosure::SCANNING);
    BOOST_CHECK_EQUAL(manifest.reached_eof, 0U);
    BOOST_REQUIRE(manager.InstallGCFloor(
        target,
        FloorAuthorization(history.second_checkpoint_height + 10,
                           80'626),
        error, context));

    std::vector<uint256> durable_prefix;
    durable_prefix.reserve(128);
    for (std::size_t i{0}; i < 128; ++i) {
        durable_prefix.push_back(manifest.candidates[i].key);
    }
    BOOST_REQUIRE(
        test::PQRegistryManagerTestAccess::EraseExactDiskSnapshots(
            manager, durable_prefix));
    manager.SnapshotDatabase()
        .FailNextSynchronousFlushBatchForTesting();
    BOOST_CHECK(!manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
    BOOST_CHECK(error.result == PQRegistryResult::PERSISTENCE_FAILED);

    PQRegistryDiskSnapshot last;
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, manifest.candidates.back().key, last));
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
    std::size_t remaining_side_records{0};
    for (const auto& side_hash : side_hashes) {
        remaining_side_records +=
            test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
                manager, side_hash, last)
            ? 1
            : 0;
    }
    BOOST_CHECK_EQUAL(remaining_side_records, 1U);
}

BOOST_AUTO_TEST_CASE(gc_erase_manifest_rejects_gaps_and_tampering)
{
    EmptyRootedGCHistory history{80'650};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    for (uint32_t tag{80'651}; tag <= 80'653; ++tag) {
        const CBlock side{Block(
            history.blocks.front().hashPrevBlock, tag,
            {OrdinaryTransaction(tag)})};
        BOOST_REQUIRE(manager.ProcessBlock(
            side, history.config.preparation_height,
            Members(history.genesis, {}, {}, CKeyID{}), {},
            /*fJustCheck=*/false, error));
    }
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        target, manifest, error));
    BOOST_REQUIRE_EQUAL(manifest.candidates.size(), 3U);
    BOOST_REQUIRE(manager.InstallGCFloor(
        target,
        FloorAuthorization(history.second_checkpoint_height + 10,
                           80'654),
        error, context));

    auto false_empty_eof{manifest};
    false_empty_eof.scan_through.reset();
    false_empty_eof.candidates.clear();
    BOOST_REQUIRE(false_empty_eof.IsValid());
    BOOST_CHECK(!manager.EraseGCManifest(
        target, std::nullopt, context, false_empty_eof, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);

    auto wrong_hash{manifest};
    wrong_hash.candidates.front().exact_record_hash =
        NonNullHash(80'655);
    BOOST_CHECK(!manager.EraseGCManifest(
        target, std::nullopt, context, wrong_hash, error));
    BOOST_CHECK(error.result == PQRegistryResult::SNAPSHOT_CORRUPT);

    auto omitted{manifest};
    omitted.candidates.erase(omitted.candidates.begin() + 1);
    BOOST_CHECK(!manager.EraseGCManifest(
        target, std::nullopt, context, omitted, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);

    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::EraseExactDiskSnapshot(
        manager, manifest.candidates[1].key));
    BOOST_CHECK(!manager.EraseGCManifest(
        target, std::nullopt, context, manifest, error));
    BOOST_CHECK(error.result == PQRegistryResult::FLOOR_CONFLICT);
    PQRegistryDiskSnapshot disk;
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, manifest.candidates.front().key, disk));
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, manifest.candidates.back().key, disk));
}

BOOST_AUTO_TEST_CASE(gc_erase_empty_resume_ignores_later_above_floor_record)
{
    EmptyRootedGCHistory history{80'675};
    auto& manager{*history.manager};
    PQRegistryError error;
    const auto context{
        history.Context(history.initial_checkpoint_height)};
    BOOST_REQUIRE(manager.FlushForGC(error));

    evo::AuxiliaryHistoryGCComponent probe_target;
    evo::PQRegistryGCEraseManifest probe_manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, std::nullopt,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        probe_target, probe_manifest, error));
    BOOST_REQUIRE_EQUAL(probe_manifest.reached_eof, 1U);
    BOOST_REQUIRE(probe_manifest.scan_through);

    evo::PQRegistryGCClosure previous_closure;
    BOOST_REQUIRE(manager.BuildGCFloorClosure(
        /*generation=*/1, probe_manifest.scan_through, context,
        /*previous=*/nullptr, previous_closure, error));
    BOOST_REQUIRE_EQUAL(previous_closure.scan_complete,
                        evo::PQRegistryGCClosure::SCANNING);
    const auto previous{FloorComponent(previous_closure)};

    evo::AuxiliaryHistoryGCComponent target;
    evo::PQRegistryGCEraseManifest manifest;
    BOOST_REQUIRE(manager.BuildGCEraseBatch(
        context, previous,
        evo::PQRegistryGCEraseManifest::MAX_CANDIDATES,
        /*max_candidates=*/256,
        target, manifest, error));
    const auto target_closure{
        evo::DecodePQRegistryGCClosure(target.closure)};
    BOOST_REQUIRE(target_closure);
    BOOST_CHECK_EQUAL(target_closure->scan_complete,
                      evo::PQRegistryGCClosure::COMPLETE);
    BOOST_CHECK(manifest.from_cursor == probe_manifest.scan_through);
    BOOST_CHECK(!manifest.scan_through);
    BOOST_CHECK_EQUAL(manifest.reached_eof, 1U);
    BOOST_CHECK(manifest.candidates.empty());

    const auto authorization{FloorAuthorization(
        history.second_checkpoint_height + 10, 80'676)};
    BOOST_REQUIRE(manager.InstallGCFloor(
        previous, authorization, error, context));
    BOOST_REQUIRE(manager.InstallGCFloor(
        target, authorization, error, context));

    std::optional<CBlock> later;
    const auto& checkpoint{context.rooted_segment.back()};
    for (uint32_t tag{800'000}; tag < 900'000; ++tag) {
        CBlock candidate{Block(
            checkpoint.block_hash, tag,
            {OrdinaryTransaction(tag)})};
        if (*manifest.from_cursor < candidate.GetHash()) {
            later = std::move(candidate);
            break;
        }
    }
    BOOST_REQUIRE(later);
    BOOST_REQUIRE(manager.ProcessBlock(
        *later, checkpoint.height + 1,
        Members(history.genesis, {}, {}, CKeyID{}), {},
        /*fJustCheck=*/false, error));
    BOOST_REQUIRE(manager.FlushForGC(error));

    PQRegistryDiskSnapshot disk;
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, later->GetHash(), disk));
    BOOST_REQUIRE(manager.EraseGCManifest(
        target, previous, context, manifest, error));
    BOOST_REQUIRE(test::PQRegistryManagerTestAccess::ReadExactDiskSnapshot(
        manager, later->GetHash(), disk));
}


BOOST_AUTO_TEST_SUITE_END()
