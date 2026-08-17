// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <chain.h>
#include <script/script.h>
#include <coins.h>
#include <consensus/validation.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <evo/deterministicmns.h>
#include <evo/pq_providertx.h>
#include <chainparams.h>
#include <dbwrapper.h>
#include <llmq/quorums_commitment.h>
#include <masternode/masternodemeta.h>
#include <streams.h>
#include <test/util/random.h>
#include <version.h>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class ScopedDiskDBPath
{
public:
    ScopedDiskDBPath()
        : path{fs::temp_directory_path() /
               (std::string{"syscoin_dmn_test_"} +
                g_insecure_rand_ctx.rand256().ToString())}
    {
    }

    ~ScopedDiskDBPath() { fs::remove_all(path); }

    const fs::path path;
};

static uint256 MakeSnapshotKey(int height)
{
    return ArithToUint256(arith_uint256(height + 1));
}

static CDeterministicMNList MakeSnapshot(int height)
{
    const uint256 block_hash = MakeSnapshotKey(height);
    return CDeterministicMNList(block_hash, height, 0);
}

static CKeyID MakeAnchorKeyID(uint8_t seed)
{
    CKeyID key_id;
    for (size_t i = 0; i < key_id.size(); ++i) {
        key_id.begin()[i] = seed + i;
    }
    return key_id;
}

static CDeterministicMNCPtr MakeAnchorMN(uint64_t internal_id, uint32_t tag)
{
    auto dmn = std::make_shared<CDeterministicMN>(internal_id);
    dmn->proTxHash = ArithToUint256(arith_uint256{0x1000 + tag});
    dmn->collateralOutpoint = COutPoint(
        ArithToUint256(arith_uint256{0x2000 + tag}), tag + 1);
    dmn->nOperatorReward = 1000 + tag;

    auto state = std::make_shared<CDeterministicMNState>();
    state->nVersion = tag % 2 == 0 ? CProRegTx::BASIC_BLS_VERSION
                                   : CProRegTx::LEGACY_BLS_VERSION;
    state->nRegisteredHeight = 100 + tag;
    state->nCollateralHeight = 80 + tag;
    state->nLastPaidHeight = 200 + tag;
    state->nPoSePenalty = 3 + tag;
    state->nPoSeRevivedHeight = 90 + tag;
    state->nRevocationReason = tag;
    state->confirmedHash = ArithToUint256(arith_uint256{0x3000 + tag});
    state->confirmedHashWithProRegTxHash =
        ArithToUint256(arith_uint256{0x4000 + tag});
    state->keyIDOwner = MakeAnchorKeyID(0x10 * tag);
    std::array<uint8_t, CLegacyBLSPublicKey::SERIALIZED_SIZE> operator_key;
    operator_key.fill(static_cast<uint8_t>(0x30 + tag));
    BOOST_REQUIRE(state->pubKeyOperator.SetBytes(operator_key));
    state->keyIDVoting = MakeAnchorKeyID(0x20 + 0x10 * tag);
    state->scriptPayout = CScript() << OP_DUP << std::vector<unsigned char>{
        static_cast<unsigned char>(tag), 0xa5};
    state->scriptOperatorPayout = CScript() << OP_HASH160 << std::vector<unsigned char>{
        0x5a, static_cast<unsigned char>(tag)};
    if (tag == 2) state->BanIfNotBanned(300 + tag);
    state->vchNEVMAddress = {
        static_cast<unsigned char>(tag), 0x55, 0xaa,
        static_cast<unsigned char>(tag + 1)};
    dmn->pdmnState = std::move(state);
    return dmn;
}

static CDeterministicMNCPtr MakeLegacyReplayMN(
    uint64_t internal_id, uint32_t tag)
{
    const auto source{MakeAnchorMN(internal_id, tag)};
    auto dmn{std::make_shared<CDeterministicMN>(internal_id)};
    dmn->proTxHash = source->proTxHash;
    dmn->collateralOutpoint = source->collateralOutpoint;
    dmn->nOperatorReward = source->nOperatorReward;
    auto state{std::make_shared<CDeterministicMNState>(*source->pdmnState)};
    state->Revive(0);
    state->nPoSeRevivedHeight = -1;
    dmn->pdmnState = std::move(state);
    return dmn;
}

template <std::size_t Size>
static std::array<uint8_t, Size> FilledLegacyBytes(uint8_t value)
{
    std::array<uint8_t, Size> bytes;
    bytes.fill(value);
    return bytes;
}

static llmq::CFinalCommitmentTxPayload MakeLegacyReplayCommitment(
    uint32_t height,
    const uint256& quorum_hash,
    std::size_t invalid_member)
{
    llmq::CFinalCommitmentTxPayload payload;
    payload.nHeight = height;
    payload.commitment = llmq::CFinalCommitment{quorum_hash};
    payload.commitment.nVersion = llmq::CFinalCommitment::GetVersion(true);
    payload.commitment.signers.assign(
        payload.commitment.signers.size(), true);
    payload.commitment.validMembers.assign(
        payload.commitment.validMembers.size(), true);
    BOOST_REQUIRE(invalid_member < payload.commitment.validMembers.size());
    payload.commitment.validMembers[invalid_member] = false;
    BOOST_REQUIRE(payload.commitment.quorumPublicKey.SetBytes(
        FilledLegacyBytes<48>(1)));
    payload.commitment.quorumVvecHash = uint256::ONEV;
    BOOST_REQUIRE(payload.commitment.quorumSig.SetBytes(
        FilledLegacyBytes<96>(2)));
    BOOST_REQUIRE(payload.commitment.membersSig.SetBytes(
        FilledLegacyBytes<96>(3)));
    return payload;
}

static CDeterministicMNList MakeNontrivialAnchorSnapshot(
    const uint256& block_hash, int height, bool reverse_insertion)
{
    CDeterministicMNList snapshot(block_hash, height, 17);
    std::array<CDeterministicMNCPtr, 3> members{
        MakeAnchorMN(9, 1), MakeAnchorMN(2, 2), MakeAnchorMN(14, 3)};
    if (reverse_insertion) std::reverse(members.begin(), members.end());
    for (const auto& member : members) snapshot.AddMN(member, /*fBumpTotalCount=*/false);
    return snapshot;
}

static void WriteSnapshotRange(CDeterministicMNManager& manager, int start_height, int count)
{
    for (int i = 0; i < count; ++i) {
        const int height = start_height + i;
        manager.m_evoDb->WriteCache(MakeSnapshotKey(height), MakeSnapshot(height));
    }
}

struct SnapshotIndexChain {
    int start_height{0};
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> indices;

    const CBlockIndex* Tip() const
    {
        return indices.empty() ? nullptr : &indices.back();
    }

    const CBlockIndex* At(int height) const
    {
        return &indices.at(height - start_height);
    }
};

static SnapshotIndexChain BuildSnapshotIndexChain(int start_height, int count)
{
    SnapshotIndexChain chain{start_height, std::vector<uint256>(count), std::vector<CBlockIndex>(count)};
    for (int i = 0; i < count; ++i) {
        const int height = start_height + i;
        chain.hashes[i] = MakeSnapshotKey(height);
        chain.indices[i].nHeight = height;
        chain.indices[i].pprev = i == 0 ? nullptr : &chain.indices[i - 1];
        chain.indices[i].phashBlock = &chain.hashes[i];
    }
    return chain;
}

static CTransactionRef MakeProviderMutationTransaction(
    int32_t transaction_version, const uint256& pro_tx_hash, uint32_t tag)
{
    CMutableTransaction tx;
    tx.nVersion = transaction_version;
    tx.vin.emplace_back(COutPoint{MakeSnapshotKey(10'000 + tag), tag});
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);

    if (transaction_version == SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        CProUpServTx payload;
        payload.nVersion = CProUpServTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.inputsHash = MakeSnapshotKey(20'000 + tag);
        payload.globalKeyVersion = 1;
        payload.pqSig[0] = 1;
        SetTxPayload(tx, payload);
    } else if (transaction_version == SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR) {
        CProUpRegTx payload;
        payload.nVersion = CProUpRegTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.keyIDVoting = MakeAnchorKeyID(0x70);
        payload.inputsHash = MakeSnapshotKey(20'000 + tag);
        payload.vchSig.assign(1, 1);
        SetTxPayload(tx, payload);
    } else {
        BOOST_REQUIRE_EQUAL(transaction_version,
                            SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE);
        CProUpRevTx payload;
        payload.nVersion = CProUpRevTx::PQ_VERSION;
        payload.proTxHash = pro_tx_hash;
        payload.inputsHash = MakeSnapshotKey(20'000 + tag);
        payload.globalKeyVersion = 1;
        payload.pqSig[0] = 1;
        SetTxPayload(tx, payload);
    }
    return MakeTransactionRef(std::move(tx));
}

static CBlock MakeProviderMutationBlock(
    std::initializer_list<CTransactionRef> transactions)
{
    CBlock block;
    block.vtx.emplace_back(MakeTransactionRef(CMutableTransaction{}));
    block.vtx.insert(block.vtx.end(), transactions.begin(), transactions.end());
    return block;
}

BOOST_AUTO_TEST_SUITE(evo_dmn_db_maintenance_tests)

BOOST_AUTO_TEST_CASE(unavailable_and_corrupt_negative_heights_are_null)
{
    CDeterministicMNList unavailable;
    BOOST_CHECK(unavailable.IsNull());
    unavailable.SetHeight(0);
    BOOST_CHECK(!unavailable.IsNull());
    BOOST_CHECK_EQUAL(unavailable.GetHeight(), 0);

    CDataStream encoded{SER_DISK, PROTOCOL_VERSION};
    const uint256 block_hash{MakeSnapshotKey(0)};
    const int corrupt_height{-2};
    const uint32_t total_registered_count{0};
    encoded << block_hash << corrupt_height << total_registered_count;
    WriteCompactSize(encoded, 0);
    CDeterministicMNList corrupt;
    encoded >> corrupt;
    BOOST_CHECK(corrupt.IsNull());
}

// SYSCOIN: Prove the genesis-active base survives bounded-window maintenance.
BOOST_AUTO_TEST_CASE(dip3_at_genesis_persists_only_the_canonical_empty_base)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreDIP3Heights {
        Consensus::Params& consensus;
        int activation{consensus.DIP0003Height};
        int enforcement{consensus.DIP0003EnforcementHeight};
        ~RestoreDIP3Heights()
        {
            consensus.DIP0003Height = activation;
            consensus.DIP0003EnforcementHeight = enforcement;
        }
    } restore{consensus};
    consensus.DIP0003Height = 0;
    consensus.DIP0003EnforcementHeight = 0;

    const uint256 genesis_hash{consensus.hashGenesisBlock};
    auto chain{BuildSnapshotIndexChain(
        /*start_height=*/0, CDeterministicMNManager::LIST_CACHE_SIZE + 2)};
    chain.hashes.front() = genesis_hash;
    const CBlockIndex* genesis_index{chain.At(0)};
    const CBlockIndex* first_child{chain.At(1)};

    const ScopedDiskDBPath disk_db;
    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    {
        CDeterministicMNManager manager(db_params);
        BOOST_CHECK(!manager.HasPersistentWindow());
        BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), 1);
        BOOST_CHECK_EQUAL(manager.m_evoDb->GetReadCacheSize(), 0U);
        const auto snapshot{manager.GetListForBlock(genesis_index)};
        BOOST_CHECK(!snapshot.IsNull());
        BOOST_CHECK_EQUAL(snapshot.GetHeight(), 0);
        BOOST_CHECK(snapshot.GetBlockHash() == genesis_hash);
        BOOST_CHECK_EQUAL(snapshot.GetAllMNsCount(), 0U);
        BOOST_CHECK_EQUAL(snapshot.GetTotalRegisteredCount(), 0U);
        BOOST_CHECK_THROW(manager.GetListForBlock(first_child),
                          std::runtime_error);
    }

    db_params.wipe_data = false;
    {
        CDeterministicMNManager genesis_only_restart(db_params);
        BOOST_CHECK(!genesis_only_restart.HasPersistentWindow());
        BOOST_CHECK_EQUAL(
            genesis_only_restart.m_evoDb->CountPersistedEntries(), 1);
        BOOST_CHECK_EQUAL(
            genesis_only_restart.m_evoDb->GetReadCacheSize(), 0U);
        const auto snapshot{
            genesis_only_restart.GetListForBlock(genesis_index)};
        BOOST_CHECK(!snapshot.IsNull());
        BOOST_CHECK_EQUAL(snapshot.GetHeight(), 0);
        BOOST_CHECK(snapshot.GetBlockHash() == genesis_hash);
        BOOST_CHECK_EQUAL(snapshot.GetAllMNsCount(), 0U);
        BOOST_CHECK_EQUAL(snapshot.GetTotalRegisteredCount(), 0U);
        BOOST_CHECK_THROW(
            genesis_only_restart.GetListForBlock(first_child),
            std::runtime_error);

        BOOST_REQUIRE(genesis_only_restart.m_evoDb->WriteThrough(
            first_child->GetBlockHash(),
            CDeterministicMNList{first_child->GetBlockHash(), 1, 0},
            /*fSync=*/true));
        for (int height{2}; height <= chain.Tip()->nHeight; ++height) {
            const auto* index{chain.At(height)};
            genesis_only_restart.m_evoDb->WriteCache(
                index->GetBlockHash(),
                CDeterministicMNList{index->GetBlockHash(), height, 0});
        }
        genesis_only_restart.UpdatedBlockTip(chain.Tip());
        BOOST_REQUIRE(genesis_only_restart.FlushCacheToDisk(
            /*bForceFlush=*/true));
        BOOST_CHECK(genesis_only_restart.HasPersistentWindow());
        BOOST_CHECK_EQUAL(
            genesis_only_restart.m_evoDb->CountPersistedEntries(),
            CDeterministicMNManager::LIST_CACHE_SIZE + 1);
        CDeterministicMNList persisted;
        BOOST_CHECK(genesis_only_restart.m_evoDb->Read(genesis_hash,
                                                       persisted));
        BOOST_CHECK(!genesis_only_restart.m_evoDb->Read(
            first_child->GetBlockHash(), persisted));
        BOOST_CHECK_THROW(genesis_only_restart.GetListForBlock(first_child),
                          std::runtime_error);
    }

    {
        CDeterministicMNManager restarted(db_params);
        BOOST_CHECK(!restarted.HasPersistentWindow());
        const auto snapshot{restarted.GetListForBlock(genesis_index)};
        BOOST_CHECK(!snapshot.IsNull());
        BOOST_CHECK_EQUAL(snapshot.GetHeight(), 0);
        BOOST_CHECK(snapshot.GetBlockHash() == genesis_hash);
        BOOST_CHECK_EQUAL(snapshot.GetAllMNsCount(), 0U);
        BOOST_CHECK_EQUAL(snapshot.GetTotalRegisteredCount(), 0U);
        BOOST_CHECK_THROW(restarted.GetListForBlock(first_child),
                          std::runtime_error);
        restarted.UpdatedBlockTip(chain.Tip());
        BOOST_REQUIRE(restarted.FlushCacheToDisk(/*bForceFlush=*/true));
        BOOST_CHECK(restarted.HasPersistentWindow());
        BOOST_REQUIRE(restarted.m_evoDb->WriteThrough(
            genesis_hash, CDeterministicMNList{genesis_hash, 0, 1},
            /*fSync=*/true));
    }
    BOOST_CHECK_THROW(CDeterministicMNManager{db_params},
                      std::runtime_error);
}

BOOST_AUTO_TEST_CASE(first_dip3_just_check_validates_pq_without_persisting)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestorePQDeployment {
        Consensus::Params& consensus;
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t registration_cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future_horizon{consensus.nPQFutureHorizonEpochs};
        int anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 anchor_mn_state{consensus.hashPQLegacyMNState};
        uint256 anchor_pq_state{consensus.hashPQLegacyPQRegistryState};
        ~RestorePQDeployment()
        {
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = registration_cutoff;
            consensus.nPQFutureHorizonEpochs = future_horizon;
            consensus.nPQLegacyAnchorHeight = anchor_height;
            consensus.hashPQLegacyAnchorBlock = anchor_block;
            consensus.hashPQLegacyMNState = anchor_mn_state;
            consensus.hashPQLegacyPQRegistryState = anchor_pq_state;
        }
    } restore{consensus};
    consensus.nPQPreparationHeight = std::numeric_limits<int>::max();
    consensus.nPQChainLockEpochOrigin = std::numeric_limits<int>::max();
    consensus.nPQRegistrationCutoffBlocks = 0;
    consensus.nPQFutureHorizonEpochs = 0;
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQLegacyAnchorBlock.SetNull();
    consensus.hashPQLegacyMNState.SetNull();
    consensus.hashPQLegacyPQRegistryState.SetNull();

    const int active_height{consensus.DIP0003Height};
    BOOST_REQUIRE_GT(active_height, 0);
    const uint256 parent_hash{MakeSnapshotKey(active_height - 1)};
    CBlockIndex parent_index;
    parent_index.nHeight = active_height - 1;
    parent_index.phashBlock = &parent_hash;

    auto db_params = DBParams{
        .path = "testdb_dmn_first_dip3_just_check",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    BOOST_CHECK(manager.GetListForBlock(&parent_index).IsNull());

    CMutableTransaction pq_transaction;
    pq_transaction.nVersion = llmq::pq::PQ_GLOBAL_KEY_TX_VERSION;
    CBlock rejected_block{MakeProviderMutationBlock(
        {MakeTransactionRef(std::move(pq_transaction))})};
    rejected_block.hashPrevBlock = parent_hash;
    rejected_block.nNonce = 1;
    const uint256 rejected_hash{rejected_block.GetHash()};
    CBlockIndex rejected_index;
    rejected_index.nHeight = active_height;
    rejected_index.pprev = &parent_index;
    rejected_index.phashBlock = &rejected_hash;

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
    BlockValidationState rejected_state;
    CDeterministicMNListNEVMAddressDiff rejected_diff;
    BOOST_CHECK(!manager.ProcessBlock(
        rejected_block, &rejected_index, rejected_state, view,
        no_legacy_commitment, rejected_diff,
        /*fJustCheck=*/true, /*ibd=*/true));
    BOOST_CHECK_EQUAL(rejected_state.GetRejectReason(),
                      "bad-pq-registry-disabled");
    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->ReadCache(rejected_hash, snapshot));

    CBlock accepted_block{MakeProviderMutationBlock({})};
    accepted_block.hashPrevBlock = parent_hash;
    accepted_block.nNonce = 2;
    const uint256 accepted_hash{accepted_block.GetHash()};
    CBlockIndex accepted_index;
    accepted_index.nHeight = active_height;
    accepted_index.pprev = &parent_index;
    accepted_index.phashBlock = &accepted_hash;

    BlockValidationState accepted_state;
    CDeterministicMNListNEVMAddressDiff accepted_diff;
    BOOST_REQUIRE(manager.ProcessBlock(
        accepted_block, &accepted_index, accepted_state, view,
        no_legacy_commitment, accepted_diff,
        /*fJustCheck=*/true, /*ibd=*/true));
    BOOST_CHECK(!manager.m_evoDb->ReadCache(accepted_hash, snapshot));
}

BOOST_AUTO_TEST_CASE(pq_payment_eligibility_follows_consensus_ban_state)
{
    const auto clone_with_state = [](const CDeterministicMNCPtr& source,
                                     std::shared_ptr<CDeterministicMNState> state) {
        auto result{std::make_shared<CDeterministicMN>(source->GetInternalId())};
        result->proTxHash = source->proTxHash;
        result->collateralOutpoint = source->collateralOutpoint;
        result->nOperatorReward = source->nOperatorReward;
        result->pdmnState = std::move(state);
        return CDeterministicMNCPtr{std::move(result)};
    };

    // A valid pre-anchor member remains a payee even when no external PQ
    // operator state exists. Missing child-key participation is not PoSe.
    const auto migrated{MakeLegacyReplayMN(20, 5)};
    CDeterministicMNList migrated_list{MakeSnapshotKey(500), 500, 1};
    migrated_list.AddMN(migrated, /*fBumpTotalCount=*/false);
    BOOST_REQUIRE(migrated_list.GetMNPayee());
    BOOST_CHECK(migrated_list.GetMNPayee()->proTxHash == migrated->proTxHash);

    // A new PQ ProRegTx is consensus-banned until an active global key and a
    // later service update revive it, so collateral alone earns no payment.
    const auto source{MakeLegacyReplayMN(21, 6)};
    auto preregistration_state{
        std::make_shared<CDeterministicMNState>(*source->pdmnState)};
    preregistration_state->nVersion = CProRegTx::PQ_VERSION;
    preregistration_state->pubKeyOperator.SetNull();
    preregistration_state->BanIfNotBanned(501);
    const auto preregistration{
        clone_with_state(source, preregistration_state)};
    CDeterministicMNList preregistration_list{MakeSnapshotKey(501), 501, 1};
    preregistration_list.AddMN(preregistration, /*fBumpTotalCount=*/false);
    BOOST_CHECK_EQUAL(preregistration_list.GetValidMNsCount(), 0U);
    BOOST_CHECK(!preregistration_list.GetMNPayee());

    auto activated_state{
        std::make_shared<CDeterministicMNState>(*preregistration->pdmnState)};
    activated_state->Revive(502);
    const auto activated{clone_with_state(source, activated_state)};
    CDeterministicMNList activated_list{MakeSnapshotKey(502), 502, 1};
    activated_list.AddMN(activated, /*fBumpTotalCount=*/false);
    BOOST_CHECK_EQUAL(activated_list.GetValidMNsCount(), 1U);
    BOOST_REQUIRE(activated_list.GetMNPayee());
    BOOST_CHECK(activated_list.GetMNPayee()->proTxHash == activated->proTxHash);
}

BOOST_AUTO_TEST_CASE(payment_probation_is_reflected_in_projected_payees)
{
    std::array<CDeterministicMNCPtr, 3> members{
        MakeLegacyReplayMN(30, 10), MakeLegacyReplayMN(31, 11),
        MakeLegacyReplayMN(32, 12)};
    CDeterministicMNList list{MakeSnapshotKey(510), 510, 3};
    for (const auto& member : members) {
        list.AddMN(member, /*fBumpTotalCount=*/false);
    }

    llmq::pq::PQPaymentProbationState partial;
    partial.entries = {{members[0]->proTxHash, 2},
                       {members[2]->proTxHash, 2}};
    std::sort(partial.entries.begin(), partial.entries.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    BOOST_REQUIRE(partial.IsStructurallyValid());
    const auto projected{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), &partial)};
    BOOST_REQUIRE_EQUAL(projected.size(), 1U);
    BOOST_CHECK(projected.front()->proTxHash == members[1]->proTxHash);

    llmq::pq::PQPaymentProbationState all;
    for (const auto& member : members) {
        all.entries.push_back({member->proTxHash, 2});
    }
    std::sort(all.entries.begin(), all.entries.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    BOOST_REQUIRE(all.IsStructurallyValid());
    const auto fallback{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), &all)};
    const auto ordinary{list.GetProjectedMNPayees()};
    BOOST_CHECK(fallback == ordinary);
}

BOOST_AUTO_TEST_CASE(outbound_probe_failures_do_not_mutate_pose_or_payments)
{
    const auto member{MakeLegacyReplayMN(22, 7)};
    CDeterministicMNList list{MakeSnapshotKey(503), 503, 1};
    list.AddMN(member, /*fBumpTotalCount=*/false);

    const int penalty_before{member->pdmnState->nPoSePenalty};
    const int ban_height_before{member->pdmnState->GetBannedHeight()};
    const int revived_height_before{member->pdmnState->nPoSeRevivedHeight};
    CMasternodeMetaInfo metadata{member->proTxHash};
    for (int attempt{0};
         attempt <= MASTERNODE_MAX_FAILED_OUTBOUND_ATTEMPTS; ++attempt) {
        metadata.SetLastOutboundAttempt(attempt + 1);
    }
    BOOST_CHECK(metadata.OutboundFailedTooManyTimes());

    const auto after{list.GetMN(member->proTxHash)};
    BOOST_REQUIRE(after);
    BOOST_CHECK_EQUAL(after->pdmnState->nPoSePenalty, penalty_before);
    BOOST_CHECK_EQUAL(after->pdmnState->GetBannedHeight(), ban_height_before);
    BOOST_CHECK_EQUAL(after->pdmnState->nPoSeRevivedHeight,
                      revived_height_before);
    BOOST_CHECK(list.IsMNValid(*after));
    BOOST_REQUIRE(list.GetMNPayee());
    BOOST_CHECK(list.GetMNPayee()->proTxHash == member->proTxHash);
}

BOOST_AUTO_TEST_CASE(pq_legacy_state_hash_v1_is_order_independent_and_pinned)
{
    const uint256 genesis_hash = ArithToUint256(arith_uint256{0xabcdef});
    const uint256 block_hash = ArithToUint256(arith_uint256{0x123456});
    const auto forward = MakeNontrivialAnchorSnapshot(block_hash, 4321, false);
    const auto reverse = MakeNontrivialAnchorSnapshot(block_hash, 4321, true);

    const uint256 digest = forward.GetPQLegacyStateHash(genesis_hash);
    BOOST_CHECK(digest == reverse.GetPQLegacyStateHash(genesis_hash));
    BOOST_CHECK_EQUAL(
        digest.ToString(),
        "1a57c3f045901d8750b060fb692223e47d5ffbbf0cf0e1737ab41ab2b90f9989");
}

BOOST_AUTO_TEST_CASE(pq_anchor_write_through_survives_dirty_cache_eviction)
{
    SelectParams(ChainType::MAIN);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int old_anchor_height = consensus.nPQLegacyAnchorHeight;
    const uint256 old_anchor_block = consensus.hashPQLegacyAnchorBlock;
    const uint256 old_anchor_state = consensus.hashPQLegacyMNState;
    const uint256 old_anchor_pq_state =
        consensus.hashPQLegacyPQRegistryState;
    struct RestoreAnchorParams {
        Consensus::Params& consensus;
        int height;
        uint256 block;
        uint256 state;
        uint256 pq_state;
        ~RestoreAnchorParams()
        {
            consensus.nPQLegacyAnchorHeight = height;
            consensus.hashPQLegacyAnchorBlock = block;
            consensus.hashPQLegacyMNState = state;
            consensus.hashPQLegacyPQRegistryState = pq_state;
        }
    } restore{consensus, old_anchor_height, old_anchor_block, old_anchor_state,
              old_anchor_pq_state};

    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = consensus.DIP0003Height;
    const int anchor_height = start_height + 1;
    const int snapshot_count = cache_limit + 32;
    const auto chain = BuildSnapshotIndexChain(start_height, snapshot_count);
    const uint256 anchor_hash = MakeSnapshotKey(anchor_height);
    const auto anchor_snapshot =
        MakeNontrivialAnchorSnapshot(anchor_hash, anchor_height, false);

    consensus.nPQLegacyAnchorHeight = anchor_height;
    consensus.hashPQLegacyAnchorBlock = anchor_hash;
    consensus.hashPQLegacyMNState = anchor_snapshot.GetPQLegacyStateHash(
        consensus.hashGenesisBlock);
    const auto empty_pq_state =
        llmq::pq::PQRegistrySnapshot{}.RecomputeConsensusStateRoot(
            consensus.hashGenesisBlock);
    BOOST_REQUIRE(empty_pq_state);
    consensus.hashPQLegacyPQRegistryState = *empty_pq_state;

    auto db_params = DBParams{
        .path = "testdb_dmn_pq_anchor_write_through",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        anchor_hash, anchor_snapshot, /*fSync=*/true));

    for (int i = 0; i < snapshot_count; ++i) {
        const int height = start_height + i;
        if (height == anchor_height) continue;
        manager.m_evoDb->WriteCache(MakeSnapshotKey(height), MakeSnapshot(height));
    }
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->GetReadWriteCacheSize(), static_cast<size_t>(cache_limit));
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));

    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), cache_limit + 1);
    BOOST_CHECK(manager.VerifyPersistedSnapshot(chain.At(anchor_height)));
    BOOST_CHECK(manager.VerifyPQLegacyAnchorState(chain.At(anchor_height)));

    CDeterministicMNList persisted;
    BOOST_REQUIRE(manager.m_evoDb->Read(anchor_hash, persisted));
    BOOST_CHECK(::SerializeHash(persisted) == ::SerializeHash(anchor_snapshot));
    BOOST_CHECK(
        persisted.GetPQLegacyStateHash(consensus.hashGenesisBlock) ==
        consensus.hashPQLegacyMNState);

    consensus.hashPQLegacyMNState = uint256::ONEV;
    BOOST_CHECK(!manager.VerifyPQLegacyAnchorState(chain.At(anchor_height)));
}

BOOST_AUTO_TEST_CASE(non_forced_flush_does_not_persist_snapshots_during_ibd)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;

    auto db_params = DBParams{
        .path = "testdb_dmn_ibd_no_persist",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto chain = BuildSnapshotIndexChain(start_height, cache_limit);
    manager.UpdatedBlockTip(chain.Tip());

    WriteSnapshotRange(manager, start_height, cache_limit);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/false));

    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), 0);
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetReadWriteCacheSize(), static_cast<size_t>(cache_limit));
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetEraseCacheSize(), 0U);
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetReadCacheSize(), 0U);
    BOOST_CHECK(!manager.HasPersistentWindow());
}

BOOST_AUTO_TEST_CASE(pending_snapshot_sync_flush_orders_prior_write_through)
{
    SelectParams(ChainType::MAIN);
    auto db_params = DBParams{
        .path = "testdb_dmn_pending_sync_barrier",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const int height{Params().GetConsensus().DIP0003Height};
    const uint256 block_hash{MakeSnapshotKey(height)};

    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        block_hash, MakeSnapshot(height), /*fSync=*/false));
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetReadWriteCacheSize(), 0U);

    manager.m_evoDb->FailNextFlushBatchForTesting();
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/false));
    BOOST_CHECK_THROW(
        manager.FlushPendingSnapshotsToDisk(/*fSync=*/true),
        dbwrapper_error);
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
}

BOOST_AUTO_TEST_CASE(first_forced_flush_initializes_persisted_window_and_hot_cache)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;
    const int total_snapshots = cache_limit + 8;
    const int oldest_retained_height = start_height + total_snapshots - cache_limit;

    auto db_params = DBParams{
        .path = "testdb_dmn_init_window",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto chain = BuildSnapshotIndexChain(start_height, total_snapshots);
    manager.UpdatedBlockTip(chain.Tip());

    WriteSnapshotRange(manager, start_height, total_snapshots);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));

    BOOST_CHECK(manager.HasPersistentWindow());
    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), cache_limit);
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetReadWriteCacheSize(), 0U);
    BOOST_CHECK_EQUAL(manager.m_evoDb->GetEraseCacheSize(), 0U);
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->GetReadCacheSize(),
        static_cast<size_t>(CDeterministicMNManager::HOT_LIST_CACHE_SIZE));

    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(MakeSnapshotKey(oldest_retained_height - 1), snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(oldest_retained_height), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), oldest_retained_height);
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(start_height + total_snapshots - 1), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height + total_snapshots - 1);
}

BOOST_AUTO_TEST_CASE(subsequent_forced_flush_appends_and_prunes_without_rewrite)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;
    const ScopedDiskDBPath disk_db;

    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);

    const auto initial_chain = BuildSnapshotIndexChain(start_height, cache_limit + 1);
    manager.UpdatedBlockTip(initial_chain.Tip());
    WriteSnapshotRange(manager, start_height, cache_limit + 1);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK(manager.HasPersistentWindow());

    const auto extended_chain = BuildSnapshotIndexChain(start_height, cache_limit + 2);
    manager.UpdatedBlockTip(extended_chain.Tip());
    WriteSnapshotRange(manager, start_height + cache_limit + 1, 1);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));

    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), cache_limit);
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->GetReadCacheSize(),
        static_cast<size_t>(CDeterministicMNManager::HOT_LIST_CACHE_SIZE));

    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(MakeSnapshotKey(start_height + 1), snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(start_height + 2), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height + 2);
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(start_height + cache_limit + 1), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height + cache_limit + 1);

    fs::path backup_path = db_params.path;
    backup_path += ".rewrite-backup";
    fs::path marker_path = db_params.path;
    marker_path += ".rewrite-in-progress";
    BOOST_CHECK(!fs::exists(backup_path));
    BOOST_CHECK(!fs::exists(marker_path));
}

BOOST_AUTO_TEST_CASE(older_snapshot_reads_fall_back_to_disk_after_hot_cache_shrink)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;
    const int total_snapshots = cache_limit + CDeterministicMNManager::HOT_LIST_CACHE_SIZE + 1;
    const int fallback_height =
        start_height + total_snapshots - CDeterministicMNManager::HOT_LIST_CACHE_SIZE - 1;

    auto db_params = DBParams{
        .path = "testdb_dmn_hot_cache_fallback",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto chain = BuildSnapshotIndexChain(start_height, total_snapshots);
    manager.UpdatedBlockTip(chain.Tip());

    WriteSnapshotRange(manager, start_height, total_snapshots);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));

    const CDeterministicMNList snapshot = manager.GetListForBlock(chain.At(fallback_height));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), fallback_height);
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->GetReadCacheSize(),
        static_cast<size_t>(CDeterministicMNManager::HOT_LIST_CACHE_SIZE));
}

BOOST_AUTO_TEST_CASE(replay_floor_retains_all_persisted_branches_until_clear)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;
    const int total_snapshots = cache_limit + 40;
    const int replay_floor = start_height + 20;

    auto db_params = DBParams{
        .path = "testdb_dmn_replay_retention",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto chain = BuildSnapshotIndexChain(start_height, total_snapshots);
    manager.UpdatedBlockTip(chain.Tip());

    // SYSCOIN: Model the marker publication barrier: every dirty fork-local
    // snapshot is durable before the replay floor is made live.
    constexpr int flush_chunk{256};
    for (int offset{0}; offset < total_snapshots; offset += flush_chunk) {
        const int count{std::min(flush_chunk, total_snapshots - offset)};
        WriteSnapshotRange(manager, start_height + offset, count);
        BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
    }
    const int side_height{replay_floor + 5};
    const uint256 side_hash{MakeSnapshotKey(start_height + total_snapshots + 100)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        side_hash, CDeterministicMNList{side_hash, side_height, 0},
        /*fSync=*/true));

    BOOST_CHECK_EQUAL(
        manager.UpdateReplaySnapshotRetentionFloor(replay_floor),
        replay_floor);
    BOOST_CHECK_EQUAL(
        manager.UpdateReplaySnapshotRetentionFloor(replay_floor + 100),
        replay_floor);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));

    CDeterministicMNList snapshot;
    BOOST_REQUIRE(manager.m_evoDb->Read(side_hash, snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), side_height);
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(start_height), snapshot));

    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(start_height + 10),
        start_height + 10);
    BOOST_CHECK_EQUAL(manager.UpdateReplaySnapshotRetentionFloor(std::nullopt),
                      std::numeric_limits<int>::max());
    // SYSCOIN: Value-aware finality retention preserves fork snapshots at or
    // above its floor after paired replay clears.
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_REQUIRE(manager.m_evoDb->Read(side_hash, snapshot));

    const int replacement_floor{chain.Tip()->nHeight - 10};
    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(replacement_floor),
        replacement_floor);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK(!manager.m_evoDb->Read(side_hash, snapshot));
    BOOST_CHECK(!manager.m_evoDb->Read(MakeSnapshotKey(start_height), snapshot));

    const int recent_side_height{chain.Tip()->nHeight - 5};
    const uint256 recent_side_hash{
        MakeSnapshotKey(start_height + total_snapshots + 101)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        recent_side_hash,
        CDeterministicMNList{recent_side_hash, recent_side_height, 0},
        /*fSync=*/true));
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_REQUIRE(manager.m_evoDb->Read(recent_side_hash, snapshot));

    const uint256 pending_side_hash{
        MakeSnapshotKey(start_height + total_snapshots + 102)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        pending_side_hash,
        CDeterministicMNList{pending_side_hash, side_height, 0},
        /*fSync=*/true));
    manager.UpdateFinalitySnapshotPublicationRetention(true);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_REQUIRE(manager.m_evoDb->Read(pending_side_hash, snapshot));

    manager.BeginFinalitySnapshotVerificationRetention();
    manager.UpdateFinalitySnapshotPublicationRetention(false);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_REQUIRE(manager.m_evoDb->Read(pending_side_hash, snapshot));
    manager.EndFinalitySnapshotVerificationRetention();
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK(!manager.m_evoDb->Read(pending_side_hash, snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(recent_side_hash, snapshot));

    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(chain.Tip()->nHeight),
        chain.Tip()->nHeight);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK(!manager.m_evoDb->Read(recent_side_hash, snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(
        MakeSnapshotKey(start_height + total_snapshots - 1), snapshot));

    const uint256 corrupt_key{
        MakeSnapshotKey(start_height + total_snapshots + 103)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        corrupt_key, CDeterministicMNList{side_hash, chain.Tip()->nHeight, 0},
        /*fSync=*/true));
    manager.BeginFinalitySnapshotVerificationRetention();
    manager.EndFinalitySnapshotVerificationRetention();
    BOOST_CHECK(!manager.FlushCacheToDisk(/*bForceFlush=*/true));
}

BOOST_AUTO_TEST_CASE(replay_floor_writes_through_a_long_null_receipt_tail)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int anchor_height{consensus.nPQLegacyAnchorHeight};
        ~RestoreProfile()
        {
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = anchor_height;
        }
    } restore{consensus};
    consensus.nPQPreparationHeight = std::numeric_limits<int>::max();
    consensus.nPQChainLockEpochOrigin = std::numeric_limits<int>::max();
    consensus.nPQRegistrationCutoffBlocks = 0;
    consensus.nPQFutureHorizonEpochs = 0;
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();

    const int start_height{consensus.DIP0003Height};
    const int tail_length{CDeterministicMNManager::LIST_CACHE_SIZE + 25};
    std::vector<uint256> hashes(static_cast<size_t>(tail_length + 1));
    std::vector<CBlockIndex> indices(static_cast<size_t>(tail_length + 1));
    hashes[0] = MakeSnapshotKey(start_height);
    indices[0].nHeight = start_height;
    indices[0].phashBlock = &hashes[0];
    const ScopedDiskDBPath disk_db;

    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    {
        CDeterministicMNManager manager(db_params);
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            hashes[0], CDeterministicMNList{hashes[0], start_height, 0},
            /*fSync=*/true));
        BOOST_CHECK_EQUAL(
            manager.UpdateReplaySnapshotRetentionFloor(start_height),
            start_height);

        CCoinsView base_view;
        CCoinsViewCache view(&base_view);
        const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
        for (int offset{1}; offset <= tail_length; ++offset) {
            CBlock block{MakeProviderMutationBlock({})};
            block.hashPrevBlock = hashes[static_cast<size_t>(offset - 1)];
            block.nTime = static_cast<uint32_t>(offset + 1);
            block.nNonce = static_cast<uint32_t>(offset);
            hashes[static_cast<size_t>(offset)] = block.GetHash();
            auto& index{indices[static_cast<size_t>(offset)]};
            index.nHeight = start_height + offset;
            index.pprev = &indices[static_cast<size_t>(offset - 1)];
            index.phashBlock = &hashes[static_cast<size_t>(offset)];

            BlockValidationState state;
            CDeterministicMNListNEVMAddressDiff diff;
            BOOST_REQUIRE(manager.ProcessBlock(
                block, &index, state, view, no_legacy_commitment, diff,
                /*fJustCheck=*/false, /*ibd=*/true));
        }
        BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(),
                          tail_length + 1);
    }

    // SYSCOIN: A crash-restored marker reopens snapshots written after more
    // than one dirty-FIFO window even though no later non-null receipt moved it.
    db_params.wipe_data = false;
    CDeterministicMNManager restarted(db_params);
    BOOST_CHECK_EQUAL(
        restarted.UpdateReplaySnapshotRetentionFloor(start_height),
        start_height);
    CDeterministicMNList snapshot;
    BOOST_REQUIRE(restarted.m_evoDb->Read(hashes.front(), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height);
    BOOST_REQUIRE(restarted.m_evoDb->Read(hashes.back(), snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height + tail_length);
}

BOOST_AUTO_TEST_CASE(finality_roster_cutoffs_survive_branch_churn)
{
    SelectParams(ChainType::MAIN);
    constexpr uint32_t roster_lag{288};
    const int64_t minimum_origin{
        static_cast<int64_t>(Params().GetConsensus().DIP0003Height) +
        roster_lag};
    const int64_t aligned_origin{
        ((minimum_origin + llmq::pq::PQ_EPOCH_ALIGNMENT - 1) /
         llmq::pq::PQ_EPOCH_ALIGNMENT) *
        llmq::pq::PQ_EPOCH_ALIGNMENT};
    BOOST_REQUIRE_LE(aligned_origin,
                     std::numeric_limits<int32_t>::max());
    const llmq::pq::ChainLockScheduleConfig schedule{
        .epoch_origin = static_cast<int32_t>(aligned_origin)};
    const auto roster_height{
        llmq::pq::RegistrationCutoffHeight(schedule, 5, roster_lag)};
    BOOST_REQUIRE(roster_height);
    BOOST_REQUIRE(llmq::pq::IsRegistrationCutoffHeight(
        schedule, roster_lag, *roster_height));
    BOOST_CHECK(!llmq::pq::IsRegistrationCutoffHeight(
        schedule, roster_lag, *roster_height + 1));

    const int ordinary_branch_writes{
        CDeterministicMNManager::LIST_CACHE_SIZE + 25};
    const auto branch_hash = [](int offset) {
        return ArithToUint256(arith_uint256{
            static_cast<uint64_t>(0x100000 + offset)});
    };
    const ScopedDiskDBPath disk_db;

    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    {
        CDeterministicMNManager manager(db_params);
        BOOST_CHECK_EQUAL(
            manager.UpdateFinalitySnapshotRetentionFloor(*roster_height),
            *roster_height);
        for (int offset{0}; offset < 2; ++offset) {
            const uint256 hash{branch_hash(offset)};
            BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
                hash, CDeterministicMNList{hash, *roster_height, 0},
                /*fSync=*/true));
        }

        // SYSCOIN: Only exact roster cutoffs bypass the lossy ordinary FIFO.
        // More than one complete window of non-cutoff branch churn therefore
        // cannot evict either persisted roster, without making IBD retain a
        // full DMN list for every historical block.
        const int ordinary_height{*roster_height + 1};
        for (int offset{0}; offset < ordinary_branch_writes; ++offset) {
            const uint256 hash{branch_hash(100 + offset)};
            manager.m_evoDb->WriteCache(
                hash, CDeterministicMNList{hash, ordinary_height, 0});
        }
        BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), 2);
        CDeterministicMNList snapshot;
        BOOST_REQUIRE(manager.m_evoDb->Read(branch_hash(0), snapshot));
        BOOST_CHECK(snapshot.GetBlockHash() == branch_hash(0));
        BOOST_REQUIRE(manager.m_evoDb->Read(branch_hash(1), snapshot));
        BOOST_CHECK(snapshot.GetBlockHash() == branch_hash(1));
    }

    db_params.wipe_data = false;
    CDeterministicMNManager restarted(db_params);
    CDeterministicMNList snapshot;
    BOOST_REQUIRE(restarted.m_evoDb->Read(branch_hash(0), snapshot));
    BOOST_CHECK(snapshot.GetBlockHash() == branch_hash(0));
    BOOST_REQUIRE(restarted.m_evoDb->Read(branch_hash(1), snapshot));
    BOOST_CHECK(snapshot.GetBlockHash() == branch_hash(1));
    BOOST_CHECK(!restarted.m_evoDb->Read(branch_hash(100), snapshot));
    BOOST_REQUIRE(restarted.m_evoDb->Read(
        branch_hash(100 + ordinary_branch_writes - 1), snapshot));
}

BOOST_AUTO_TEST_CASE(finality_roster_process_block_uses_sparse_write_through)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t registration_cutoff{consensus.nPQRegistrationCutoffBlocks};
        int roster_lag{consensus.nPQRosterSnapshotLag};
        uint32_t future_horizon{consensus.nPQFutureHorizonEpochs};
        int anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 anchor_mn_state{consensus.hashPQLegacyMNState};
        uint256 anchor_pq_state{consensus.hashPQLegacyPQRegistryState};
        ~RestoreProfile()
        {
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = registration_cutoff;
            consensus.nPQRosterSnapshotLag = roster_lag;
            consensus.nPQFutureHorizonEpochs = future_horizon;
            consensus.nPQLegacyAnchorHeight = anchor_height;
            consensus.hashPQLegacyAnchorBlock = anchor_block;
            consensus.hashPQLegacyMNState = anchor_mn_state;
            consensus.hashPQLegacyPQRegistryState = anchor_pq_state;
        }
    } restore{consensus};

    constexpr int roster_lag{288};
    const int64_t minimum_origin{
        static_cast<int64_t>(consensus.DIP0003Height) + 2 * roster_lag};
    const int64_t aligned_origin{
        ((minimum_origin + llmq::pq::PQ_EPOCH_ALIGNMENT - 1) /
         llmq::pq::PQ_EPOCH_ALIGNMENT) *
        llmq::pq::PQ_EPOCH_ALIGNMENT};
    BOOST_REQUIRE_LE(aligned_origin,
                     std::numeric_limits<int32_t>::max());
    consensus.nPQChainLockEpochOrigin = static_cast<int>(aligned_origin);
    consensus.nPQRegistrationCutoffBlocks = roster_lag;
    consensus.nPQRosterSnapshotLag = roster_lag;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQPreparationHeight =
        consensus.nPQChainLockEpochOrigin - roster_lag - 1;
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQLegacyAnchorBlock.SetNull();
    consensus.hashPQLegacyMNState.SetNull();
    consensus.hashPQLegacyPQRegistryState.SetNull();

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);
    const int preparation_height{consensus.nPQPreparationHeight};
    const int roster_height{preparation_height + 1};
    BOOST_REQUIRE(!llmq::pq::IsRegistrationCutoffHeight(
        registry_config.schedule, roster_lag, preparation_height));
    BOOST_REQUIRE(llmq::pq::IsRegistrationCutoffHeight(
        registry_config.schedule, roster_lag, roster_height));

    auto db_params = DBParams{
        .path = "testdb_dmn_sparse_roster_write_through",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const uint256 parent_hash{MakeSnapshotKey(preparation_height - 1)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        parent_hash,
        CDeterministicMNList{
            parent_hash, preparation_height - 1, 0},
        /*fSync=*/true));
    BOOST_CHECK_EQUAL(manager.UpdateFinalitySnapshotRetentionFloor(
                          preparation_height),
                      preparation_height);
    manager.m_evoDb->FailNextWriteThroughForTesting();

    CBlockIndex parent_index;
    parent_index.nHeight = preparation_height - 1;
    parent_index.phashBlock = &parent_hash;
    CBlock preparation_block{MakeProviderMutationBlock({})};
    preparation_block.hashPrevBlock = parent_hash;
    preparation_block.nTime = 1;
    preparation_block.nNonce = 1;
    const uint256 preparation_hash{preparation_block.GetHash()};
    CBlockIndex preparation_index;
    preparation_index.nHeight = preparation_height;
    preparation_index.pprev = &parent_index;
    preparation_index.phashBlock = &preparation_hash;

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
    BlockValidationState preparation_state;
    CDeterministicMNListNEVMAddressDiff preparation_diff;
    BOOST_REQUIRE(manager.ProcessBlock(
        preparation_block, &preparation_index, preparation_state, view,
        no_legacy_commitment, preparation_diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(preparation_hash, snapshot));

    CBlock roster_block{MakeProviderMutationBlock({})};
    roster_block.hashPrevBlock = preparation_hash;
    roster_block.nTime = 2;
    roster_block.nNonce = 2;
    const uint256 roster_hash{roster_block.GetHash()};
    CBlockIndex roster_index;
    roster_index.nHeight = roster_height;
    roster_index.pprev = &preparation_index;
    roster_index.phashBlock = &roster_hash;

    // SYSCOIN: The hook remains armed across the non-cutoff block and fires
    // only at the exact roster cutoff. Its exception must be a local runtime
    // error, never a consensus-invalid verdict, and a retry must persist it.
    BlockValidationState failed_state;
    CDeterministicMNListNEVMAddressDiff failed_diff;
    BOOST_CHECK(!manager.ProcessBlock(
        roster_block, &roster_index, failed_state, view,
        no_legacy_commitment, failed_diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    BOOST_CHECK(failed_state.IsError());
    BOOST_CHECK(!failed_state.IsInvalid());
    BOOST_CHECK_EQUAL(failed_state.GetRejectReason(), "failed-dmn-persist");
    BOOST_CHECK(!manager.m_evoDb->Read(roster_hash, snapshot));

    BlockValidationState retry_state;
    CDeterministicMNListNEVMAddressDiff retry_diff;
    BOOST_REQUIRE(manager.ProcessBlock(
        roster_block, &roster_index, retry_state, view,
        no_legacy_commitment, retry_diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    BOOST_REQUIRE(manager.m_evoDb->Read(roster_hash, snapshot));
    BOOST_CHECK(snapshot.GetBlockHash() == roster_hash);
}

BOOST_AUTO_TEST_CASE(pq_revoke_provider_mutation_conflicts_are_order_independent)
{
    SelectParams(ChainType::REGTEST);
    const int parent_height = Params().GetConsensus().DIP0003Height;
    const uint256 parent_hash{MakeSnapshotKey(parent_height)};
    CBlockIndex parent_index;
    parent_index.nHeight = parent_height;
    parent_index.phashBlock = &parent_hash;

    auto db_params = DBParams{
        .path = "testdb_dmn_pq_revoke_conflicts",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    CDeterministicMNList parent_list(parent_hash, parent_height, 1);
    const auto member{MakeAnchorMN(1, 1)};
    parent_list.AddMN(member, /*fBumpTotalCount=*/false);
    manager.m_evoDb->WriteCache(parent_hash, parent_list);

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const auto revoke{MakeProviderMutationTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE, member->proTxHash, 1)};
    const auto service{MakeProviderMutationTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE, member->proTxHash, 2)};
    const auto registrar{MakeProviderMutationTransaction(
        SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR, member->proTxHash, 3)};
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;

    auto check_conflict = [&](const CBlock& block) {
        BlockValidationState state;
        CDeterministicMNList next_list;
        CDeterministicMNList old_list;
        BOOST_CHECK(!manager.BuildNewListFromBlock(
            block, &parent_index, state, view, next_list, old_list,
            no_legacy_commitment));
        BOOST_CHECK_EQUAL(state.GetRejectReason(),
                          "bad-protx-pq-revoke-conflict");
    };
    check_conflict(MakeProviderMutationBlock({revoke, service}));
    check_conflict(MakeProviderMutationBlock({service, revoke}));
    check_conflict(MakeProviderMutationBlock({revoke, registrar}));
    check_conflict(MakeProviderMutationBlock({registrar, revoke}));

    BlockValidationState state;
    CDeterministicMNList next_list;
    CDeterministicMNList old_list;
    BOOST_REQUIRE(manager.BuildNewListFromBlock(
        MakeProviderMutationBlock({revoke}), &parent_index, state, view,
        next_list, old_list, no_legacy_commitment));
    const auto revoked{next_list.GetMN(member->proTxHash)};
    BOOST_REQUIRE(revoked);
    BOOST_CHECK(revoked->pdmnState->IsBanned());
}

BOOST_AUTO_TEST_CASE(opaque_legacy_participation_penalties_replay_through_anchor)
{
    SelectParams(ChainType::REGTEST);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    const int old_anchor_height{consensus.nPQLegacyAnchorHeight};
    const uint256 old_anchor_block{consensus.hashPQLegacyAnchorBlock};
    const uint256 old_anchor_state{consensus.hashPQLegacyMNState};
    const uint256 old_anchor_pq_state{consensus.hashPQLegacyPQRegistryState};
    struct RestoreAnchorParams {
        Consensus::Params& consensus;
        int height;
        uint256 block;
        uint256 state;
        uint256 pq_state;
        ~RestoreAnchorParams()
        {
            consensus.nPQLegacyAnchorHeight = height;
            consensus.hashPQLegacyAnchorBlock = block;
            consensus.hashPQLegacyMNState = state;
            consensus.hashPQLegacyPQRegistryState = pq_state;
        }
    } restore{consensus, old_anchor_height, old_anchor_block,
              old_anchor_state, old_anchor_pq_state};

    const int replay_interval{
        consensus.legacyQuorumReplay.session_interval};
    BOOST_REQUIRE_GT(replay_interval, 0);
    BOOST_REQUIRE_GE(consensus.DIP0003Height, 0);
    // SYSCOIN: Test fixtures may override DIP3 to a non-session boundary, but
    // the commitment must reference the exact replay base selected by consensus.
    const int64_t base_height_wide{
        ((static_cast<int64_t>(consensus.DIP0003Height) +
          replay_interval - 1) /
         replay_interval) * replay_interval};
    BOOST_REQUIRE_GE(base_height_wide, consensus.DIP0003Height);
    BOOST_REQUIRE_LE(
        base_height_wide + replay_interval - 1,
        static_cast<int64_t>(std::numeric_limits<int>::max()));
    const int base_height{static_cast<int>(base_height_wide)};
    const int anchor_height{base_height + replay_interval - 1};
    const auto chain{BuildSnapshotIndexChain(
        base_height, anchor_height - base_height + 1)};
    consensus.nPQLegacyAnchorHeight = anchor_height;
    consensus.hashPQLegacyAnchorBlock =
        chain.At(anchor_height)->GetBlockHash();
    consensus.hashPQLegacyMNState = uint256::ONEV;
    consensus.hashPQLegacyPQRegistryState = uint256::TWOV;

    auto db_params = DBParams{
        .path = "testdb_dmn_opaque_legacy_penalties",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    std::array<CDeterministicMNCPtr, 3> source_members{
        MakeLegacyReplayMN(1, 1), MakeLegacyReplayMN(2, 3),
        MakeLegacyReplayMN(3, 4)};

    auto make_list = [&](int height) {
        CDeterministicMNList list{
            chain.At(height)->GetBlockHash(), height,
            static_cast<uint32_t>(source_members.size())};
        for (const auto& member : source_members) {
            list.AddMN(member, /*fBumpTotalCount=*/false);
        }
        return list;
    };
    const auto base_list{make_list(base_height)};
    const auto parent_list{make_list(anchor_height - 1)};
    const auto anchor_list{make_list(anchor_height)};
    manager.m_evoDb->WriteCache(chain.At(base_height)->GetBlockHash(),
                                base_list);
    manager.m_evoDb->WriteCache(
        chain.At(anchor_height - 1)->GetBlockHash(), parent_list);
    manager.m_evoDb->WriteCache(chain.At(anchor_height)->GetBlockHash(),
                                anchor_list);

    const auto roster{base_list.CalculateQuorum(
        static_cast<std::size_t>(consensus.legacyQuorumReplay.size),
        chain.At(base_height)->GetBlockHash())};
    BOOST_REQUIRE_EQUAL(roster.size(), source_members.size());
    constexpr std::size_t invalid_member{1};
    const auto commitment{MakeLegacyReplayCommitment(
        static_cast<uint32_t>(anchor_height),
        chain.At(base_height)->GetBlockHash(), invalid_member)};

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const CBlock empty_block{MakeProviderMutationBlock({})};
    BlockValidationState state;
    CDeterministicMNList next_list;
    CDeterministicMNList old_list;
    BOOST_REQUIRE(manager.BuildNewListFromBlock(
        empty_block, chain.At(anchor_height - 1), state, view, next_list,
        old_list, commitment));
    const auto punished{next_list.GetMN(roster[invalid_member]->proTxHash)};
    BOOST_REQUIRE(punished);
    BOOST_CHECK_EQUAL(punished->pdmnState->nPoSePenalty,
                      next_list.CalcPenalty(66));
    for (std::size_t i{0}; i < roster.size(); ++i) {
        if (i == invalid_member) continue;
        const auto member{next_list.GetMN(roster[i]->proTxHash)};
        BOOST_REQUIRE(member);
        BOOST_CHECK_EQUAL(member->pdmnState->nPoSePenalty, 0);
    }

    auto truncated{commitment};
    truncated.commitment.validMembers.pop_back();
    BlockValidationState malformed_state;
    BOOST_CHECK(!manager.BuildNewListFromBlock(
        empty_block, chain.At(anchor_height - 1), malformed_state, view,
        next_list, old_list, truncated));
    BOOST_CHECK_EQUAL(malformed_state.GetRejectReason(), "bad-qc-structure");

    auto retired{commitment};
    retired.nHeight = static_cast<uint32_t>(anchor_height + 1);
    BlockValidationState retired_state;
    BOOST_CHECK(!manager.BuildNewListFromBlock(
        empty_block, chain.At(anchor_height), retired_state, view, next_list,
        old_list, retired));
    BOOST_CHECK_EQUAL(retired_state.GetRejectReason(), "bad-qc-retired");
}

BOOST_AUTO_TEST_SUITE_END()
