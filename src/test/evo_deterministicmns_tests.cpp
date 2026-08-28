// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <chain.h>
#include <script/script.h>
#include <coins.h>
#include <consensus/pq_migration_config.h> // SYSCOIN: Exercise crash-restored PQ anchor ancestry.
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
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>
#include <version.h>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <initializer_list>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

static fs::path SiblingDBPath(const fs::path& path, std::string_view suffix)
{
    fs::path sibling{path.parent_path()};
    sibling /= fs::PathFromString(
        fs::PathToString(path.filename()) + std::string{suffix});
    return sibling;
}

static uint64_t DirectorySizeBytes(const fs::path& path)
{
    uint64_t total{0};
    std::error_code error;
    for (auto entry = fs::recursive_directory_iterator(path, error);
         !error && entry != fs::recursive_directory_iterator();
         entry.increment(error)) {
        if (!entry->is_regular_file(error) || error) continue;
        total += entry->file_size(error);
        if (error) return 0;
    }
    return error ? 0 : total;
}

class ScopedDiskDBPath
{
public:
    ScopedDiskDBPath()
        : path{fs::temp_directory_path() /
               (std::string{"syscoin_dmn_test_"} +
                g_insecure_rand_ctx.rand256().ToString())}
    {
    }

    ~ScopedDiskDBPath()
    {
        std::error_code error;
        fs::remove_all(path, error);
        error.clear();
        fs::remove_all(SiblingDBPath(path, "_inverse"), error);
        error.clear();
        fs::remove_all(
            SiblingDBPath(path, "_pq_payment_probation"), error);
        error.clear();
        fs::remove_all(SiblingDBPath(path, "_pq_registry"), error);
        error.clear();
        fs::remove_all(SiblingDBPath(path, "_aux_gc"), error);
    }

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

static uint256 MakeOrderedSnapshotKey(uint8_t prefix, uint64_t ordinal)
{
    uint256 key;
    key.SetNull();
    key.begin()[0] = prefix;
    for (size_t i{0}; i < sizeof(ordinal); ++i) {
        key.begin()[i + 1] = static_cast<uint8_t>(ordinal >> (8 * i));
    }
    return key;
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

    CBlockIndex* At(int height)
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

static SnapshotIndexChain BuildForkedSnapshotIndexChain(
    SnapshotIndexChain& parent,
    int fork_height,
    int tip_height,
    uint8_t salt)
{
    const int start_height{fork_height + 1};
    const int count{tip_height - fork_height};
    SnapshotIndexChain chain{
        start_height, std::vector<uint256>(count),
        std::vector<CBlockIndex>(count)};
    for (int i{0}; i < count; ++i) {
        const int height{start_height + i};
        chain.hashes[i] = MakeSnapshotKey(height);
        chain.hashes[i].begin()[31] ^= salt;
        chain.hashes[i].begin()[30] ^=
            static_cast<uint8_t>(i + 1);
        chain.indices[i].nHeight = height;
        chain.indices[i].pprev =
            i == 0 ? parent.At(fork_height) : &chain.indices[i - 1];
        chain.indices[i].phashBlock = &chain.hashes[i];
    }
    return chain;
}

static void SetProbationBitmapBit(
    llmq::pq::QuorumBitmap& bitmap, std::size_t member)
{
    bitmap[member / 8] |=
        static_cast<uint8_t>(uint8_t{1} << (member % 8));
}

static llmq::pq::PQPaymentProbationTransitionContext
MakeProbationTransitionContext(
    int parent_height,
    const std::array<uint256, 4>& special_members,
    uint32_t epoch = 1)
{
    llmq::pq::PQPaymentProbationTransitionContext context;
    context.receipt = {
        epoch, parent_height + 1,
        MakeSnapshotKey(1'000'000 + parent_height)};
    for (std::size_t member{0}; member < llmq::pq::QUORUM_SIZE; ++member) {
        context.frozen_roster[member] =
            MakeSnapshotKey(2'000'000 + static_cast<int>(member));
        if (member < llmq::pq::QUORUM_MIN_VALID) {
            SetProbationBitmapBit(context.roster_valid_members, member);
        }
    }
    context.frozen_roster[0] = special_members[0];
    context.frozen_roster[1] = special_members[1];
    context.frozen_roster[2] = special_members[2];
    context.frozen_roster[350] = special_members[3];
    SetProbationBitmapBit(context.observed_members, 0);
    SetProbationBitmapBit(context.observed_members, 1);
    SetProbationBitmapBit(context.observed_members, 2);
    return context;
}

static llmq::pq::PQPaymentProbationTransitionInput
MakeReferenceProbationInput(
    const llmq::pq::PQPaymentProbationTransitionContext& context,
    const CDeterministicMNList& list)
{
    llmq::pq::PQPaymentProbationTransitionInput input;
    static_cast<llmq::pq::PQPaymentProbationTransitionContext&>(input) =
        context;
    list.ForEachMN(false, [&](const CDeterministicMN& dmn) {
        input.existing_pro_tx_hashes.push_back(dmn.proTxHash);
        if (CDeterministicMNList::IsMNValid(dmn)) {
            input.current_valid_pro_tx_hashes.push_back(dmn.proTxHash);
        }
    });
    std::sort(input.existing_pro_tx_hashes.begin(),
              input.existing_pro_tx_hashes.end());
    std::sort(input.current_valid_pro_tx_hashes.begin(),
              input.current_valid_pro_tx_hashes.end());
    return input;
}

static uint256 CheckExactParentProbationTransition(
    CDeterministicMNManager& manager,
    const CBlockIndex& parent,
    const llmq::pq::PQPaymentProbationTransitionContext& context,
    const CDeterministicMNList& list,
    const llmq::pq::PQPaymentProbationState& previous,
    const uint256& previous_hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(::cs_main);
    const auto reference_input{MakeReferenceProbationInput(context, list)};
    BOOST_REQUIRE(reference_input.IsStructurallyValid());
    const auto expected{llmq::pq::ApplyPQPaymentProbationTransition(
        previous, reference_input)};
    BOOST_REQUIRE(expected);
    auto outcome{manager.ApplyPaymentProbationTransition(parent, context)};
    BOOST_REQUIRE(
        outcome.status ==
        llmq::pq::PQPaymentProbationTransitionStatus::READY);
    BOOST_CHECK(outcome.error == llmq::pq::PQPaymentProbationError::NONE);
    BOOST_REQUIRE(outcome.transition);
    BOOST_REQUIRE(outcome.transition->Result().State() != nullptr);
    BOOST_CHECK(*outcome.transition->Result().State() == expected->state);
    BOOST_CHECK(outcome.transition->PreviousStateHash() == previous_hash);
    BOOST_CHECK(outcome.transition->AppliedReceipt() ==
                expected->undo.applied_receipt);
    BOOST_CHECK(outcome.transition->Result().StateHash() ==
                expected->undo.applied_state_hash);

    CDataStream actual_bytes{SER_NETWORK, PROTOCOL_VERSION};
    actual_bytes << *outcome.transition->Result().State()
                 << outcome.transition->PreviousStateHash()
                 << outcome.transition->AppliedReceipt()
                 << outcome.transition->Result().StateHash();
    CDataStream expected_bytes{SER_NETWORK, PROTOCOL_VERSION};
    expected_bytes << expected->state << expected->undo.previous_state_hash
                   << expected->undo.applied_receipt
                   << expected->undo.applied_state_hash;
    BOOST_CHECK_EQUAL_COLLECTIONS(
        actual_bytes.begin(), actual_bytes.end(), expected_bytes.begin(),
        expected_bytes.end());
    return outcome.transition->Result().StateHash();
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

BOOST_FIXTURE_TEST_CASE(
    special_tx_local_error_is_not_cached_as_consensus_invalid,
    TestingSetup)
{
    LOCK(::cs_main);
    BOOST_REQUIRE(deterministicMNManager);
    CBlockIndex* parent{m_node.chainman->ActiveTip()};
    BOOST_REQUIRE(parent);

    CMutableTransaction pq_transaction;
    pq_transaction.nVersion = llmq::pq::PQ_GLOBAL_KEY_TX_VERSION;
    CBlock block{MakeProviderMutationBlock(
        {MakeTransactionRef(std::move(pq_transaction))})};
    block.hashPrevBlock = parent->GetBlockHash();
    block.nNonce = 90'001;
    const uint256 block_hash{block.GetHash()};
    CBlockIndex block_index;
    block_index.nHeight = parent->nHeight + 1;
    block_index.pprev = parent;
    block_index.phashBlock = &block_hash;

    auto saved_manager{std::move(deterministicMNManager)};
    BlockValidationState local_state;
    CDeterministicMNListNEVMAddressDiff local_diff;
    const bool local_result{ProcessSpecialTxsInBlock(
        *m_node.chainman, block, &block_index, local_state, local_diff,
        m_node.chainman->ActiveChainstate().CoinsTip(),
        /*fJustCheck=*/true, /*check_sigs=*/true, /*ibd=*/true,
        SpecialTxValidationContext::NORMAL)};
    deterministicMNManager = std::move(saved_manager);
    BOOST_CHECK(!local_result);
    BOOST_CHECK(local_state.IsError());
    BOOST_CHECK(!local_state.IsInvalid());
    BOOST_CHECK_EQUAL(local_state.GetRejectReason(),
                      "failed-pq-registry-unavailable");

    CMutableTransaction invalid_registration;
    invalid_registration.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    CBlock invalid_block{MakeProviderMutationBlock(
        {MakeTransactionRef(std::move(invalid_registration))})};
    invalid_block.hashPrevBlock = parent->GetBlockHash();
    invalid_block.nNonce = 90'002;
    const uint256 invalid_hash{invalid_block.GetHash()};
    CBlockIndex invalid_index;
    invalid_index.nHeight = parent->nHeight + 1;
    invalid_index.pprev = parent;
    invalid_index.phashBlock = &invalid_hash;
    BlockValidationState invalid_state;
    CDeterministicMNListNEVMAddressDiff invalid_diff;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(
        *m_node.chainman, invalid_block, &invalid_index, invalid_state,
        invalid_diff, m_node.chainman->ActiveChainstate().CoinsTip(),
        /*fJustCheck=*/true, /*check_sigs=*/true, /*ibd=*/true,
        SpecialTxValidationContext::NORMAL));
    BOOST_CHECK(invalid_state.IsInvalid());
    BOOST_CHECK(!invalid_state.IsError());
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

BOOST_AUTO_TEST_CASE(missing_parent_snapshot_is_local_process_error)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);

    const int parent_height{Params().GetConsensus().DIP0003Height};
    BOOST_REQUIRE_GE(parent_height, 0);
    const uint256 parent_hash{MakeSnapshotKey(parent_height)};
    CBlockIndex parent_index;
    parent_index.nHeight = parent_height;
    parent_index.phashBlock = &parent_hash;

    CBlock block{MakeProviderMutationBlock({})};
    block.hashPrevBlock = parent_hash;
    block.nNonce = 1;
    const uint256 block_hash{block.GetHash()};
    CBlockIndex block_index;
    block_index.nHeight = parent_height + 1;
    block_index.pprev = &parent_index;
    block_index.phashBlock = &block_hash;

    auto db_params = DBParams{
        .path = "testdb_dmn_missing_parent_process_error",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    BlockValidationState state;
    CDeterministicMNListNEVMAddressDiff diff;
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;

    BOOST_CHECK(!manager.ProcessBlock(
        block, &block_index, state, view, no_legacy_commitment, diff,
        /*fJustCheck=*/true, /*ibd=*/true));
    BOOST_CHECK(state.IsError());
    BOOST_CHECK(!state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "failed-dmn-parent-state");
}

BOOST_AUTO_TEST_CASE(pq_legacy_anchor_rejection_precedes_registry_commit)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestorePQDeployment {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t registration_cutoff{
            consensus.nPQRegistrationCutoffBlocks};
        uint32_t future_horizon{consensus.nPQFutureHorizonEpochs};
        int legacy_anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn_state{consensus.hashPQLegacyMNState};
        uint256 legacy_pq_state{consensus.hashPQLegacyPQRegistryState};
        int finality_anchor_height{consensus.nPQChainLockAnchorHeight};
        uint256 finality_anchor_block{consensus.hashPQChainLockAnchorBlock};
        ~RestorePQDeployment()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = registration_cutoff;
            consensus.nPQFutureHorizonEpochs = future_horizon;
            consensus.nPQLegacyAnchorHeight = legacy_anchor_height;
            consensus.hashPQLegacyAnchorBlock = legacy_anchor_block;
            consensus.hashPQLegacyMNState = legacy_mn_state;
            consensus.hashPQLegacyPQRegistryState = legacy_pq_state;
            consensus.nPQChainLockAnchorHeight = finality_anchor_height;
            consensus.hashPQChainLockAnchorBlock = finality_anchor_block;
        }
    } restore{consensus};

    constexpr int preparation_height{1295};
    constexpr int epoch_origin{1440};
    consensus.DIP0003Height = preparation_height - 1;
    consensus.nPQPreparationHeight = preparation_height;
    consensus.nPQChainLockEpochOrigin = epoch_origin;
    consensus.nPQRegistrationCutoffBlocks = 144;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQLegacyAnchorHeight = preparation_height;
    consensus.nPQChainLockAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQChainLockAnchorBlock.SetNull();

    const uint256 parent_hash{MakeSnapshotKey(preparation_height - 1)};
    CBlockIndex parent_index;
    parent_index.nHeight = preparation_height - 1;
    parent_index.phashBlock = &parent_hash;

    CBlock anchor_block{MakeProviderMutationBlock({})};
    anchor_block.hashPrevBlock = parent_hash;
    anchor_block.nTime = preparation_height;
    anchor_block.nNonce = preparation_height;
    const uint256 anchor_hash{anchor_block.GetHash()};
    CBlockIndex anchor_index;
    anchor_index.nHeight = preparation_height;
    anchor_index.pprev = &parent_index;
    anchor_index.phashBlock = &anchor_hash;

    consensus.hashPQLegacyAnchorBlock = anchor_hash;
    consensus.hashPQLegacyMNState = MakeSnapshotKey(95'000);
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(95'001);

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_pq_anchor_commit_order",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        parent_hash,
        CDeterministicMNList{parent_hash, preparation_height - 1, 0},
        /*fSync=*/true));

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
    CDeterministicMNList expected_list;
    CDeterministicMNList old_list;
    BlockValidationState build_state;
    BOOST_REQUIRE(manager.BuildNewListFromBlock(
        anchor_block, &parent_index, build_state, view, expected_list,
        old_list, no_legacy_commitment));
    expected_list.SetBlockHash(anchor_hash);
    consensus.hashPQLegacyMNState =
        expected_list.GetOrComputePQLegacyStateHash(
            consensus.hashGenesisBlock);

    llmq::pq::PQRegistryManager root_oracle{
        DBParams{
            .path = "testdb_dmn_pq_anchor_root_oracle",
            .cache_bytes = static_cast<size_t>(1 << 20),
            .memory_only = true,
            .wipe_data = true,
        },
        consensus.hashGenesisBlock, registry_config};
    llmq::pq::PQRegistryCallbacks empty_membership;
    empty_membership.dmn_exists_before = [](const uint256&) { return false; };
    empty_membership.dmn_exists_after = [](const uint256&) { return false; };
    llmq::pq::PQRegistryError registry_error;
    uint256 correct_pq_root;
    BOOST_REQUIRE(root_oracle.ProcessBlock(
        anchor_block, preparation_height, empty_membership, {},
        /*fJustCheck=*/true, registry_error, &correct_pq_root));
    BOOST_REQUIRE(!correct_pq_root.IsNull());
    consensus.hashPQLegacyPQRegistryState = correct_pq_root;
    consensus.hashPQLegacyPQRegistryState.begin()[0] ^= 1;
    BOOST_REQUIRE(!consensus.hashPQLegacyPQRegistryState.IsNull());

    manager.FailNextPQRegistryWriteThroughForTesting();
    BlockValidationState rejected_state;
    CDeterministicMNListNEVMAddressDiff rejected_diff;
    BOOST_CHECK(!manager.ProcessBlock(
        anchor_block, &anchor_index, rejected_state, view,
        no_legacy_commitment, rejected_diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    BOOST_CHECK(rejected_state.IsInvalid());
    BOOST_CHECK_EQUAL(rejected_state.GetRejectReason(),
                      "bad-pq-legacy-state");

    CDeterministicMNList dmn_snapshot;
    BOOST_CHECK(!manager.m_evoDb->ReadCache(anchor_hash, dmn_snapshot));
    CDeterministicMNManager::InverseJournalEntryStatsForTesting inverse_stats;
    BOOST_CHECK(!manager.GetInverseJournalEntryStatsForTesting(
        anchor_hash, inverse_stats));
    llmq::pq::PQRegistrySnapshot pq_snapshot;
    std::string snapshot_error;
    BOOST_CHECK(!manager.GetPQRegistrySnapshot(
        &anchor_index, pq_snapshot, snapshot_error));

    // Neither an invalid anchor nor check-only validation may consume the
    // armed journal failure. Only publication of the corrected block reaches
    // the injected local failure.
    consensus.hashPQLegacyPQRegistryState = correct_pq_root;
    BlockValidationState check_state;
    CDeterministicMNListNEVMAddressDiff check_diff;
    BOOST_REQUIRE_MESSAGE(manager.ProcessBlock(
        anchor_block, &anchor_index, check_state, view,
        no_legacy_commitment, check_diff,
        /*fJustCheck=*/true, /*ibd=*/true), check_state.ToString());
    BOOST_CHECK(!manager.m_evoDb->ReadCache(anchor_hash, dmn_snapshot));
    BOOST_CHECK(!manager.GetInverseJournalEntryStatsForTesting(
        anchor_hash, inverse_stats));
    BOOST_CHECK(!manager.GetPQRegistrySnapshot(
        &anchor_index, pq_snapshot, snapshot_error));

    BlockValidationState failed_commit_state;
    CDeterministicMNListNEVMAddressDiff failed_commit_diff;
    BOOST_CHECK(!manager.ProcessBlock(
        anchor_block, &anchor_index, failed_commit_state, view,
        no_legacy_commitment, failed_commit_diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    BOOST_CHECK(failed_commit_state.IsError());
    BOOST_CHECK(!failed_commit_state.IsInvalid());
    BOOST_CHECK_EQUAL(failed_commit_state.GetRejectReason(),
                      "failed-pq-registry-commit");
    BOOST_CHECK(!manager.m_evoDb->ReadCache(anchor_hash, dmn_snapshot));
    BOOST_CHECK(!manager.GetPQRegistrySnapshot(
        &anchor_index, pq_snapshot, snapshot_error));

    BlockValidationState accepted_state;
    CDeterministicMNListNEVMAddressDiff accepted_diff;
    BOOST_REQUIRE_MESSAGE(manager.ProcessBlock(
        anchor_block, &anchor_index, accepted_state, view,
        no_legacy_commitment, accepted_diff,
        /*fJustCheck=*/false, /*ibd=*/true), accepted_state.ToString());
    BOOST_REQUIRE(manager.m_evoDb->ReadCache(anchor_hash, dmn_snapshot));
    BOOST_CHECK(dmn_snapshot.GetBlockHash() == anchor_hash);
    BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
        anchor_hash, inverse_stats));
    BOOST_REQUIRE(manager.GetPQRegistrySnapshot(
        &anchor_index, pq_snapshot, snapshot_error));
    BOOST_CHECK(pq_snapshot.consensus_state_root == correct_pq_root);
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
    llmq::pq::PQPaymentProbationManager probation_manager{DBParams{
        .path = "testdb_dmn_payment_probation_view",
        .cache_bytes = static_cast<std::size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    }};
    std::array<CDeterministicMNCPtr, 3> members{
        MakeLegacyReplayMN(30, 10), MakeLegacyReplayMN(31, 11),
        MakeLegacyReplayMN(32, 12)};
    CDeterministicMNList list{MakeSnapshotKey(510), 510, 3};
    for (const auto& member : members) {
        list.AddMN(member, /*fBumpTotalCount=*/false);
    }
    const auto banned{MakeLegacyReplayMN(33, 13)};
    list.AddMN(banned, /*fBumpTotalCount=*/false);
    auto banned_state{
        std::make_shared<CDeterministicMNState>(*banned->pdmnState)};
    banned_state->BanIfNotBanned(510);
    list.UpdateMN(banned->proTxHash, banned_state);
    BOOST_CHECK(!list.GetValidMN(banned->proTxHash));

    llmq::pq::PQPaymentProbationState partial;
    partial.entries = {{members[0]->proTxHash, 2},
                       {members[2]->proTxHash, 2}};
    std::sort(partial.entries.begin(), partial.entries.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
    });
    BOOST_REQUIRE(partial.IsStructurallyValid());
    const auto partial_hash{
        llmq::pq::GetPQPaymentProbationStateHash(partial)};
    BOOST_REQUIRE(partial_hash);
    BOOST_REQUIRE(probation_manager.CommitState(
        partial, *partial_hash, /*fJustCheck=*/false));
    llmq::pq::PQPaymentProbationStateView partial_view;
    BOOST_REQUIRE(probation_manager.GetStateView(*partial_hash,
                                                 partial_view));
    const auto projected{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), &partial_view)};
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
    const auto all_hash{llmq::pq::GetPQPaymentProbationStateHash(all)};
    BOOST_REQUIRE(all_hash);
    BOOST_REQUIRE(probation_manager.CommitState(
        all, *all_hash, /*fJustCheck=*/false));
    llmq::pq::PQPaymentProbationStateView all_view;
    BOOST_REQUIRE(probation_manager.GetStateView(*all_hash, all_view));
    const auto fallback{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), &all_view)};
    const auto ordinary{list.GetProjectedMNPayees()};
    BOOST_CHECK(fallback == ordinary);

    // Once PQ payment eligibility is active, the audit liveness fallback is
    // confined to root-bearing operators and cannot reintroduce a rootless
    // payee.
    const auto sorted_hashes{[](std::initializer_list<uint256> hashes) {
        std::vector<uint256> result{hashes};
        std::sort(result.begin(), result.end());
        return result;
    }};
    const auto pq_payment_eligible{sorted_hashes(
        {members[1]->proTxHash, members[2]->proTxHash})};
    BOOST_REQUIRE(list.GetMNPayee(&all_view, &pq_payment_eligible));
    BOOST_CHECK(list.GetMNPayee(&all_view, &pq_payment_eligible)->proTxHash ==
                members[1]->proTxHash);
    const auto filtered_fallback{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), &all_view,
        &pq_payment_eligible)};
    const auto filtered_ordinary{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), nullptr, &pq_payment_eligible)};
    BOOST_CHECK(filtered_fallback == filtered_ordinary);
    BOOST_REQUIRE_EQUAL(filtered_fallback.size(), 2U);
    BOOST_CHECK(std::none_of(
        filtered_fallback.begin(), filtered_fallback.end(),
        [&](const auto& payee) {
            return payee->proTxHash == members[0]->proTxHash;
        }));

    // Direct PQ-set iteration must retain the old membership-filter behavior:
    // absent and PoSe-banned entries are ignored, and duplicate entries cannot
    // duplicate projected payees.
    const auto noisy_pq_payment_eligible{sorted_hashes(
        {MakeSnapshotKey(50'000), banned->proTxHash,
         members[1]->proTxHash, members[1]->proTxHash,
         members[2]->proTxHash})};
    const auto noisy_payee{
        list.GetMNPayee(&all_view, &noisy_pq_payment_eligible)};
    BOOST_REQUIRE(noisy_payee);
    BOOST_CHECK(noisy_payee->proTxHash ==
                list.GetMNPayee(&all_view, &pq_payment_eligible)->proTxHash);
    BOOST_CHECK(list.GetProjectedMNPayees(
                    std::numeric_limits<int>::max(), &all_view,
                    &noisy_pq_payment_eligible) == filtered_fallback);
    BOOST_CHECK(list.GetProjectedMNPayees(
                    std::numeric_limits<int>::max(), nullptr,
                    &noisy_pq_payment_eligible) == filtered_ordinary);
    BOOST_CHECK(list.GetProjectedMNPayees(
                    std::numeric_limits<int>::max(), &partial_view,
                    &noisy_pq_payment_eligible) ==
                list.GetProjectedMNPayees(
                    std::numeric_limits<int>::max(), &partial_view,
                    &pq_payment_eligible));

    const std::vector<uint256> no_pq_payment_eligible;
    BOOST_CHECK(!list.GetMNPayee(&all_view, &no_pq_payment_eligible));
    BOOST_CHECK(list.GetProjectedMNPayees(
                         std::numeric_limits<int>::max(), &all_view,
                         &no_pq_payment_eligible)
                    .empty());

    // SYSCOIN: Root capability gates admission only. Restoring it preserves
    // queue age, and the ordinary payment update moves the selected node back.
    const auto only_newer{sorted_hashes({members[1]->proTxHash})};
    BOOST_REQUIRE(list.GetMNPayee(nullptr, &only_newer));
    BOOST_CHECK(list.GetMNPayee(nullptr, &only_newer)->proTxHash ==
                members[1]->proTxHash);
    const auto restored{sorted_hashes(
        {members[0]->proTxHash, members[1]->proTxHash})};
    BOOST_REQUIRE(list.GetMNPayee(nullptr, &restored));
    BOOST_CHECK(list.GetMNPayee(nullptr, &restored)->proTxHash ==
                members[0]->proTxHash);
    const auto restored_projection{list.GetProjectedMNPayees(
        std::numeric_limits<int>::max(), nullptr, &restored)};
    BOOST_REQUIRE(!restored_projection.empty());
    BOOST_CHECK(restored_projection.front()->proTxHash ==
                members[0]->proTxHash);
}

// SYSCOIN: Consensus validation, templates, governance, and RPC must share
// one branch-exact payee derivation without allowing a fork or indexed
// probation root to reuse another entry.
BOOST_AUTO_TEST_CASE(exact_parent_payee_cache_is_branch_bounded)
{
    SelectParams(ChainType::REGTEST);
    auto db_params = DBParams{
        .path = "testdb_dmn_exact_parent_payee_cache",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);

    constexpr int height{520};
    const uint256 hash_a{MakeSnapshotKey(height)};
    const uint256 hash_b{MakeSnapshotKey(height + 10'000)};
    const uint256 hash_empty{MakeSnapshotKey(height + 20'000)};
    const auto member_a{MakeLegacyReplayMN(40, 20)};
    const auto member_b{MakeLegacyReplayMN(41, 21)};

    CDeterministicMNList list_a{hash_a, height, 1};
    list_a.AddMN(member_a, /*fBumpTotalCount=*/false);
    CDeterministicMNList list_b{hash_b, height, 1};
    list_b.AddMN(member_b, /*fBumpTotalCount=*/false);
    const CDeterministicMNList empty_list{hash_empty, height, 0};
    manager.m_evoDb->WriteCache(hash_a, list_a);
    manager.m_evoDb->WriteCache(hash_b, list_b);
    manager.m_evoDb->WriteCache(hash_empty, empty_list);

    CBlockIndex index_a;
    index_a.nHeight = height;
    index_a.phashBlock = &hash_a;
    CBlockIndex index_b;
    index_b.nHeight = height;
    index_b.phashBlock = &hash_b;
    CBlockIndex index_empty;
    index_empty.nHeight = height;
    index_empty.phashBlock = &hash_empty;

    CDeterministicMNCPtr payee;
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_a, payee));
    BOOST_REQUIRE(payee);
    BOOST_CHECK(payee->proTxHash == member_a->proTxHash);
    auto stats{manager.GetMNPayeeCacheStatsForTesting()};
    BOOST_CHECK_EQUAL(stats.entries, 1U);
    BOOST_CHECK_EQUAL(stats.builds, 1U);
    BOOST_CHECK_EQUAL(stats.hits, 0U);

    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_a, payee));
    BOOST_CHECK(payee->proTxHash == member_a->proTxHash);
    stats = manager.GetMNPayeeCacheStatsForTesting();
    BOOST_CHECK_EQUAL(stats.builds, 1U);
    BOOST_CHECK_EQUAL(stats.hits, 1U);

    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_b, payee));
    BOOST_REQUIRE(payee);
    BOOST_CHECK(payee->proTxHash == member_b->proTxHash);
    stats = manager.GetMNPayeeCacheStatsForTesting();
    BOOST_CHECK_EQUAL(stats.entries, 2U);
    BOOST_CHECK_EQUAL(stats.builds, 2U);
    BOOST_CHECK_EQUAL(stats.hits, 1U);

    // An empty list is a successful null result and must be cacheable too.
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_empty, payee));
    BOOST_CHECK(!payee);
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_empty, payee));
    BOOST_CHECK(!payee);
    stats = manager.GetMNPayeeCacheStatsForTesting();
    BOOST_CHECK_EQUAL(stats.entries, 3U);
    BOOST_CHECK_EQUAL(stats.builds, 3U);
    BOOST_CHECK_EQUAL(stats.hits, 2U);

    // The payment-only root is not committed by block_hash and therefore
    // participates independently in the exact-parent key.
    index_a.pqPaymentProbationStateHash = uint256::ONEV;
    BOOST_CHECK(!manager.GetMNPayeeForBlock(&index_a, payee));
    index_a.pqPaymentProbationStateHash.SetNull();
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_a, payee));
    BOOST_REQUIRE(payee);
    BOOST_CHECK(payee->proTxHash == member_a->proTxHash);
    stats = manager.GetMNPayeeCacheStatsForTesting();
    BOOST_CHECK_EQUAL(stats.builds, 3U);
    BOOST_CHECK_EQUAL(stats.hits, 3U);

    // The exact-parent hot reader shares one authenticated indexed state
    // across consumers; changing only that root creates one payee-cache key.
    llmq::pq::PQPaymentProbationState probation;
    probation.entries.push_back({member_a->proTxHash, 1, -1});
    const auto probation_hash{
        llmq::pq::GetPQPaymentProbationStateHash(probation)};
    BOOST_REQUIRE(probation_hash);
    BOOST_REQUIRE(manager.CommitPaymentProbationState(
        probation, *probation_hash, /*fJustCheck=*/false));
    index_a.pqPaymentProbationStateHash = *probation_hash;
    llmq::pq::PQPaymentProbationStateView view_a;
    llmq::pq::PQPaymentProbationStateView view_b;
    BOOST_REQUIRE(manager.GetPaymentProbationStateView(&index_a, view_a));
    BOOST_REQUIRE(manager.GetPaymentProbationStateView(&index_a, view_b));
    BOOST_CHECK(view_a.SharesStateWith(view_b));
    BOOST_CHECK_EQUAL(view_a.MissCount(member_a->proTxHash), 1U);
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_a, payee));
    BOOST_REQUIRE(payee);
    BOOST_CHECK(payee->proTxHash == member_a->proTxHash);
    BOOST_REQUIRE(manager.GetMNPayeeForBlock(&index_a, payee));
    stats = manager.GetMNPayeeCacheStatsForTesting();
    BOOST_CHECK_EQUAL(stats.builds, 4U);
    BOOST_CHECK_EQUAL(stats.hits, 4U);
}

BOOST_AUTO_TEST_CASE(
    exact_parent_probation_transition_matches_reference_on_each_branch)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto db_params = DBParams{
        .path = "testdb_dmn_exact_parent_probation_transition",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);

    const int height{std::max(Params().GetConsensus().DIP0003Height, 600)};
    const uint256 hash_a{MakeSnapshotKey(height + 30'000)};
    const uint256 hash_b{MakeSnapshotKey(height + 40'000)};
    CBlockIndex parent_a;
    parent_a.nHeight = height;
    parent_a.phashBlock = &hash_a;
    CBlockIndex parent_b;
    parent_b.nHeight = height;
    parent_b.phashBlock = &hash_b;

    const auto valid{MakeAnchorMN(100, 1)};
    const auto banned{MakeAnchorMN(101, 2)};
    const uint256 absent{MakeSnapshotKey(2'500'000)};
    const auto branch_only{MakeAnchorMN(102, 3)};
    const std::array<uint256, 4> special_members{
        valid->proTxHash, banned->proTxHash, absent,
        branch_only->proTxHash};
    const auto context{
        MakeProbationTransitionContext(height, special_members)};
    BOOST_REQUIRE(context.IsStructurallyValid());

    CDeterministicMNList list_a{hash_a, height, 2};
    list_a.AddMN(valid, /*fBumpTotalCount=*/false);
    list_a.AddMN(banned, /*fBumpTotalCount=*/false);
    CDeterministicMNList list_b{hash_b, height, 3};
    list_b.AddMN(valid, /*fBumpTotalCount=*/false);
    list_b.AddMN(banned, /*fBumpTotalCount=*/false);
    list_b.AddMN(branch_only, /*fBumpTotalCount=*/false);
    manager.m_evoDb->WriteCache(hash_a, list_a);
    manager.m_evoDb->WriteCache(hash_b, list_b);

    llmq::pq::PQPaymentProbationState previous;
    previous.entries = {
        {valid->proTxHash, 1, -1},
        {banned->proTxHash, 1, -1},
        {absent, 1, -1},
        {branch_only->proTxHash, 1, -1},
    };
    std::sort(previous.entries.begin(), previous.entries.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.pro_tx_hash < rhs.pro_tx_hash;
              });
    const auto previous_hash{
        llmq::pq::GetPQPaymentProbationStateHash(previous)};
    BOOST_REQUIRE(previous_hash);
    BOOST_REQUIRE(manager.CommitPaymentProbationState(
        previous, *previous_hash, /*fJustCheck=*/false));
    parent_a.pqPaymentProbationStateHash = *previous_hash;
    parent_b.pqPaymentProbationStateHash = *previous_hash;

    const uint256 result_a{CheckExactParentProbationTransition(
        manager, parent_a, context, list_a, previous, *previous_hash)};
    const uint256 result_b{CheckExactParentProbationTransition(
        manager, parent_b, context, list_b, previous, *previous_hash)};
    BOOST_CHECK(result_a != result_b);
    const auto outcome_a{
        manager.ApplyPaymentProbationTransition(parent_a, context)};
    const auto outcome_b{
        manager.ApplyPaymentProbationTransition(parent_b, context)};
    BOOST_REQUIRE(outcome_a.transition);
    BOOST_REQUIRE(outcome_b.transition);
    BOOST_CHECK_EQUAL(
        outcome_a.transition->Result().MissCount(valid->proTxHash), 0U);
    BOOST_CHECK_EQUAL(
        outcome_a.transition->Result().MissCount(banned->proTxHash), 0U);
    BOOST_CHECK_EQUAL(
        outcome_a.transition->Result().MissCount(absent), 0U);
    BOOST_CHECK_EQUAL(
        outcome_a.transition->Result().MissCount(branch_only->proTxHash),
        0U);
    BOOST_CHECK_EQUAL(
        outcome_b.transition->Result().MissCount(branch_only->proTxHash),
        1U);

    FastRandomContext random{true};
    for (uint32_t trial{0}; trial < 24; ++trial) {
        auto randomized_context{context};
        randomized_context.receipt.epoch = 10 + trial;
        randomized_context.receipt.receipt_id =
            MakeSnapshotKey(2'800'000 + static_cast<int>(trial));
        randomized_context.observed_members.fill(0);
        for (std::size_t member{0}; member < 3; ++member) {
            if (random.randrange(2) != 0) {
                SetProbationBitmapBit(
                    randomized_context.observed_members, member);
            }
        }

        llmq::pq::PQPaymentProbationState randomized_previous;
        for (const uint256& pro_tx_hash : special_members) {
            if (random.randrange(2) == 0) continue;
            randomized_previous.entries.push_back({
                pro_tx_hash,
                static_cast<uint8_t>(1 + random.randrange(2)), -1});
        }
        std::sort(randomized_previous.entries.begin(),
                  randomized_previous.entries.end(),
                  [](const auto& lhs, const auto& rhs) {
                      return lhs.pro_tx_hash < rhs.pro_tx_hash;
                  });
        const auto randomized_previous_hash{
            llmq::pq::GetPQPaymentProbationStateHash(randomized_previous)};
        BOOST_REQUIRE(randomized_previous_hash);
        BOOST_REQUIRE(manager.CommitPaymentProbationState(
            randomized_previous, *randomized_previous_hash,
            /*fJustCheck=*/false));
        parent_a.pqPaymentProbationStateHash = *randomized_previous_hash;
        (void)CheckExactParentProbationTransition(
            manager, parent_a, randomized_context, list_a,
            randomized_previous, *randomized_previous_hash);
    }
}

BOOST_AUTO_TEST_CASE(exact_parent_probation_transition_fails_closed)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto db_params = DBParams{
        .path = "testdb_dmn_exact_parent_probation_failures",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    using Status = llmq::pq::PQPaymentProbationTransitionStatus;
    using Error = llmq::pq::PQPaymentProbationError;

    const int height{std::max(Params().GetConsensus().DIP0003Height, 700)};
    const uint256 empty_hash{MakeSnapshotKey(height + 50'000)};
    CBlockIndex empty_parent;
    empty_parent.nHeight = height;
    empty_parent.phashBlock = &empty_hash;
    manager.m_evoDb->WriteCache(
        empty_hash, CDeterministicMNList{empty_hash, height, 0});
    const std::array<uint256, 4> special_members{
        MakeSnapshotKey(2'600'000), MakeSnapshotKey(2'600'001),
        MakeSnapshotKey(2'600'002), MakeSnapshotKey(2'600'003)};
    const auto context{
        MakeProbationTransitionContext(height, special_members)};
    const auto empty_outcome{
        manager.ApplyPaymentProbationTransition(empty_parent, context)};
    BOOST_REQUIRE(empty_outcome.status == Status::READY);
    BOOST_CHECK(empty_outcome.error == Error::NONE);
    BOOST_REQUIRE(empty_outcome.transition);
    BOOST_CHECK(empty_outcome.transition->PreviousStateHash() ==
                manager.EmptyPaymentProbationStateHash());

    // The live receipt seam must reject malformed peer context while keeping
    // unavailable exact-parent data in the local-error path below.
    auto invalid_bitmap{context};
    invalid_bitmap.roster_valid_members.fill(0);
    const auto malformed{
        manager.ApplyPaymentProbationTransition(empty_parent,
                                                 invalid_bitmap)};
    BOOST_CHECK(malformed.status == Status::INVALID);
    BOOST_CHECK(malformed.error == Error::INVALID_BITMAP);
    BOOST_CHECK(!malformed.transition);

    const uint256 missing_hash{MakeSnapshotKey(height + 60'000)};
    CBlockIndex missing_parent;
    missing_parent.nHeight = height;
    missing_parent.phashBlock = &missing_hash;
    auto wrong_height{context};
    ++wrong_height.receipt.carrier_height;
    const auto invalid{
        manager.ApplyPaymentProbationTransition(missing_parent,
                                                 wrong_height)};
    BOOST_CHECK(invalid.status == Status::INVALID);
    BOOST_CHECK(invalid.error ==
                llmq::pq::PQPaymentProbationError::INVALID_RECEIPT);
    BOOST_CHECK(!invalid.transition);

    const auto missing_snapshot{
        manager.ApplyPaymentProbationTransition(missing_parent, context)};
    BOOST_CHECK(missing_snapshot.status == Status::LOCAL_ERROR);
    BOOST_CHECK(missing_snapshot.error == Error::INVALID_STATE);
    BOOST_CHECK(!missing_snapshot.transition);

    const uint256 missing_root_hash{MakeSnapshotKey(height + 70'000)};
    CBlockIndex missing_root_parent;
    missing_root_parent.nHeight = height;
    missing_root_parent.phashBlock = &missing_root_hash;
    manager.m_evoDb->WriteCache(
        missing_root_hash,
        CDeterministicMNList{missing_root_hash, height, 0});
    missing_root_parent.pqPaymentProbationStateHash =
        MakeSnapshotKey(2'700'000);
    const auto missing_root{manager.ApplyPaymentProbationTransition(
        missing_root_parent, context)};
    BOOST_CHECK(missing_root.status == Status::LOCAL_ERROR);
    BOOST_CHECK(missing_root.error == Error::INVALID_STATE);
    BOOST_CHECK(!missing_root.transition);

    const uint256 corrupt_hash{MakeSnapshotKey(height + 80'000)};
    CBlockIndex corrupt_parent;
    corrupt_parent.nHeight = height;
    corrupt_parent.phashBlock = &corrupt_hash;
    manager.m_evoDb->WriteCache(
        corrupt_hash,
        CDeterministicMNList{MakeSnapshotKey(height + 80'001), height, 0});
    const auto corrupt_snapshot{
        manager.ApplyPaymentProbationTransition(corrupt_parent, context)};
    BOOST_CHECK(corrupt_snapshot.status == Status::LOCAL_ERROR);
    BOOST_CHECK(corrupt_snapshot.error == Error::INVALID_STATE);
    BOOST_CHECK(!corrupt_snapshot.transition);
}

// SYSCOIN: A legacy projection ends where root eligibility begins.
BOOST_AUTO_TEST_CASE(payment_projection_stops_at_root_gate)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int legacy_anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn_state{consensus.hashPQLegacyMNState};
        uint256 legacy_pq_state{consensus.hashPQLegacyPQRegistryState};
        int finality_anchor_height{consensus.nPQChainLockAnchorHeight};
        uint256 finality_anchor_block{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQLegacyAnchorHeight = legacy_anchor_height;
            consensus.hashPQLegacyAnchorBlock = legacy_anchor_block;
            consensus.hashPQLegacyMNState = legacy_mn_state;
            consensus.hashPQLegacyPQRegistryState = legacy_pq_state;
            consensus.nPQChainLockAnchorHeight = finality_anchor_height;
            consensus.hashPQChainLockAnchorBlock = finality_anchor_block;
        }
    } restore{consensus};

    constexpr int legacy_anchor_height{1300};
    constexpr int finality_anchor_height{1440};
    constexpr int parent_height{finality_anchor_height - 2};
    consensus.DIP0003Height = legacy_anchor_height - 1;
    consensus.nPQLegacyAnchorHeight = legacy_anchor_height;
    consensus.hashPQLegacyAnchorBlock = MakeSnapshotKey(80'000);
    consensus.hashPQLegacyMNState = MakeSnapshotKey(80'001);
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(80'002);
    consensus.nPQChainLockAnchorHeight = finality_anchor_height;
    consensus.hashPQChainLockAnchorBlock = MakeSnapshotKey(80'003);

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_pq_payment_projection_boundary",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    const uint256 parent_hash{MakeSnapshotKey(parent_height)};
    CDeterministicMNList list{parent_hash, parent_height, 3};
    for (uint32_t member{0}; member < 3; ++member) {
        list.AddMN(MakeLegacyReplayMN(40 + member, 20 + member),
                   /*fBumpTotalCount=*/false);
    }
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        parent_hash, list, /*fSync=*/true));

    CBlockIndex parent;
    parent.nHeight = parent_height;
    parent.phashBlock = &parent_hash;
    std::vector<CDeterministicMNCPtr> projection;
    BOOST_REQUIRE(manager.GetProjectedMNPayeesForBlock(
        &parent, 10, projection));
    BOOST_CHECK_EQUAL(projection.size(), 2U);
    BOOST_REQUIRE(manager.GetProjectedMNPayeesForBlock(
        &parent, 1, projection));
    BOOST_CHECK_EQUAL(projection.size(), 1U);
}

// SYSCOIN: A root-required projection cannot reuse one epoch's frozen set for
// the following epoch.
BOOST_AUTO_TEST_CASE(payment_projection_stops_at_frozen_epoch_boundary)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int legacy_anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn_state{consensus.hashPQLegacyMNState};
        uint256 legacy_pq_state{consensus.hashPQLegacyPQRegistryState};
        int finality_anchor_height{consensus.nPQChainLockAnchorHeight};
        uint256 finality_anchor_block{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = legacy_anchor_height;
            consensus.hashPQLegacyAnchorBlock = legacy_anchor_block;
            consensus.hashPQLegacyMNState = legacy_mn_state;
            consensus.hashPQLegacyPQRegistryState = legacy_pq_state;
            consensus.nPQChainLockAnchorHeight = finality_anchor_height;
            consensus.hashPQChainLockAnchorBlock = finality_anchor_block;
        }
    } restore{consensus};

    constexpr int preparation_height{1295};
    constexpr int epoch_origin{1440};
    constexpr int checkpoint_height{1583};
    constexpr int finality_anchor_height{1440};
    constexpr int first_parent_height{1725};
    constexpr int second_parent_height{1726};
    consensus.DIP0003Height = preparation_height - 1;
    consensus.nPQPreparationHeight = preparation_height;
    consensus.nPQChainLockEpochOrigin = epoch_origin;
    consensus.nPQRegistrationCutoffBlocks = 144;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQLegacyAnchorHeight = preparation_height;
    consensus.hashPQLegacyAnchorBlock = MakeSnapshotKey(90'000);
    consensus.hashPQLegacyMNState = MakeSnapshotKey(90'001);
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(90'002);
    consensus.nPQChainLockAnchorHeight = finality_anchor_height;
    consensus.hashPQChainLockAnchorBlock = MakeSnapshotKey(90'003);

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);
    const auto preparation_view{llmq::pq::DeriveOperatorKeyScheduleView(
        registry_config.schedule, preparation_height,
        registry_config.registration_cutoff_blocks,
        registry_config.future_horizon_epochs)};
    const auto checkpoint_view{llmq::pq::DeriveOperatorKeyScheduleView(
        registry_config.schedule, checkpoint_height,
        registry_config.registration_cutoff_blocks,
        registry_config.future_horizon_epochs)};
    BOOST_REQUIRE(preparation_view);
    BOOST_REQUIRE(checkpoint_view);

    std::array<CDeterministicMNCPtr, 3> members{
        MakeLegacyReplayMN(50, 30), MakeLegacyReplayMN(51, 31),
        MakeLegacyReplayMN(52, 32)};
    std::vector<llmq::pq::OperatorKeyState> operator_states;
    std::vector<uint256> tree_ids;
    for (std::size_t index{0}; index < members.size(); ++index) {
        llmq::pq::GlobalKeyRecord key;
        key.key_version = 1;
        key.public_key[0] = static_cast<uint8_t>(index + 1);
        key.child_key_commitment.generation = 1;
        key.child_key_commitment.first_epoch = 0;
        key.child_key_commitment.tree_id =
            MakeSnapshotKey(91'000 + static_cast<int>(index));
        key.child_key_commitment.root =
            MakeSnapshotKey(92'000 + static_cast<int>(index));
        llmq::pq::GlobalSignature proof{};
        proof[0] = 1;
        auto state{llmq::pq::OperatorKeyState::ForOperator(
            members[index]->proTxHash)};
        BOOST_REQUIRE(state.Advance(*preparation_view) ==
                      llmq::pq::OperatorKeyStateResult::OK);
        BOOST_REQUIRE(state.ApplyInitialGlobalKey(
                          *preparation_view, consensus.hashGenesisBlock, key,
                          MakeSnapshotKey(93'000 + static_cast<int>(index)),
                          proof, /*owner_authorization_verified=*/true,
                          /*check_sigs=*/false) ==
                      llmq::pq::OperatorKeyStateResult::OK);
        BOOST_REQUIRE(state.Advance(*checkpoint_view) ==
                      llmq::pq::OperatorKeyStateResult::OK);
        BOOST_REQUIRE(state.ResolveChildRoot(0).status ==
                      llmq::pq::ChildRootResolutionStatus::FROZEN_PRESENT);
        tree_ids.push_back(key.child_key_commitment.tree_id);
        operator_states.push_back(std::move(state));
    }
    std::sort(operator_states.begin(), operator_states.end(),
              [](const auto& left, const auto& right) {
                  return left.pro_tx_hash < right.pro_tx_hash;
              });
    std::sort(tree_ids.begin(), tree_ids.end());

    ScopedDiskDBPath db_path;
    DBParams manager_db{
        .path = db_path.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    DBParams registry_db{manager_db};
    registry_db.path = SiblingDBPath(manager_db.path, "_pq_registry");
    registry_db.cache_bytes =
        std::max<std::size_t>(1, registry_db.cache_bytes / 2);

    const uint256 checkpoint_parent_hash{
        MakeSnapshotKey(checkpoint_height - 1)};
    const uint256 checkpoint_hash{MakeSnapshotKey(checkpoint_height)};
    std::vector<uint256> branch_hashes{
        checkpoint_hash};
    {
        llmq::pq::PQRegistryManager registry{
            registry_db, consensus.hashGenesisBlock, registry_config};
        const auto empty_root{
            llmq::pq::PQRegistrySnapshot{}.RecomputeConsensusStateRoot(
                consensus.hashGenesisBlock)};
        BOOST_REQUIRE(empty_root);
        // SYSCOIN: Seed the same bounded authenticated checkpoint segment used
        // by production replay; a synthetic C-1 root cannot authorize C's
        // sparse operator and tree-id transition.
        uint256 previous_registry_hash{
            MakeSnapshotKey(preparation_height - 1)};
        for (int height{preparation_height}; height < checkpoint_height;
             ++height) {
            llmq::pq::PQRegistryDiskSnapshot record;
            record.is_checkpoint = static_cast<uint8_t>(
                height == preparation_height);
            record.height = height;
            record.block_hash = MakeSnapshotKey(height);
            record.previous_block_hash = previous_registry_hash;
            record.previous_consensus_state_root = *empty_root;
            record.consensus_state_root = *empty_root;
            BOOST_REQUIRE(record.IsStructurallyValid());
            BOOST_REQUIRE(registry.WriteExactSnapshotForTesting(
                record.block_hash, record));
            previous_registry_hash = record.block_hash;
        }
        BOOST_REQUIRE(previous_registry_hash == checkpoint_parent_hash);

        llmq::pq::PQRegistrySnapshot checkpoint;
        checkpoint.height = checkpoint_height;
        checkpoint.block_hash = checkpoint_hash;
        checkpoint.previous_block_hash = checkpoint_parent_hash;
        checkpoint.operator_states = operator_states;
        checkpoint.used_tree_ids = tree_ids;
        const auto checkpoint_root{checkpoint.RecomputeConsensusStateRoot(
            consensus.hashGenesisBlock)};
        BOOST_REQUIRE(checkpoint_root);
        checkpoint.consensus_state_root = *checkpoint_root;
        BOOST_REQUIRE(checkpoint.IsStructurallyValid());

        llmq::pq::PQRegistryDiskSnapshot checkpoint_disk;
        checkpoint_disk.is_checkpoint = 1;
        checkpoint_disk.height = checkpoint_height;
        checkpoint_disk.block_hash = checkpoint_hash;
        checkpoint_disk.previous_block_hash = checkpoint_parent_hash;
        checkpoint_disk.previous_consensus_state_root =
            *empty_root;
        checkpoint_disk.operator_states = operator_states;
        checkpoint_disk.checkpoint_operator_states = operator_states;
        checkpoint_disk.tree_ids = tree_ids;
        checkpoint_disk.block_tree_ids = tree_ids;
        checkpoint_disk.consensus_state_root = *checkpoint_root;
        BOOST_REQUIRE(checkpoint_disk.IsStructurallyValid());
        BOOST_REQUIRE(registry.WriteExactSnapshotForTesting(
            checkpoint_hash, checkpoint_disk));

        llmq::pq::PQRegistryCallbacks membership;
        membership.dmn_exists_before = [](const uint256&) { return true; };
        membership.dmn_exists_after = [](const uint256&) { return true; };
        uint256 previous_hash{checkpoint_hash};
        for (int height{checkpoint_height + 1};
             height <= second_parent_height; ++height) {
            CBlock block{MakeProviderMutationBlock({})};
            block.hashPrevBlock = previous_hash;
            block.nTime = static_cast<uint32_t>(height);
            block.nNonce = static_cast<uint32_t>(height);
            llmq::pq::PQRegistryError error;
            BOOST_REQUIRE_MESSAGE(registry.ProcessBlock(
                block, height, membership, {}, /*fJustCheck=*/false, error),
                llmq::pq::PQRegistryResultString(error.result));
            previous_hash = block.GetHash();
            branch_hashes.push_back(previous_hash);
        }
        BOOST_REQUIRE(registry.Flush(/*fSync=*/true));
    }

    manager_db.wipe_data = false;
    CDeterministicMNManager manager{manager_db};
    const auto branch_hash_at = [&](int height) -> const uint256& {
        return branch_hashes.at(
            static_cast<std::size_t>(height - checkpoint_height));
    };
    for (int height{first_parent_height};
         height <= second_parent_height; ++height) {
        CDeterministicMNList list{
            branch_hash_at(height), height,
            static_cast<uint32_t>(members.size())};
        for (const auto& member : members) {
            list.AddMN(member, /*fBumpTotalCount=*/false);
        }
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            branch_hash_at(height), list, /*fSync=*/true));
    }

    CBlockIndex previous;
    previous.nHeight = first_parent_height - 1;
    previous.phashBlock = &branch_hash_at(first_parent_height - 1);
    CBlockIndex first_parent;
    first_parent.nHeight = first_parent_height;
    first_parent.pprev = &previous;
    first_parent.phashBlock = &branch_hash_at(first_parent_height);
    CBlockIndex second_parent;
    second_parent.nHeight = second_parent_height;
    second_parent.pprev = &first_parent;
    second_parent.phashBlock = &branch_hash_at(second_parent_height);

    std::vector<CDeterministicMNCPtr> projection;
    BOOST_REQUIRE(manager.GetProjectedMNPayeesForBlock(
        &first_parent, 20, projection));
    BOOST_CHECK_EQUAL(projection.size(), 2U);
    BOOST_REQUIRE(manager.GetProjectedMNPayeesForBlock(
        &second_parent, 20, projection));
    BOOST_CHECK_EQUAL(projection.size(), 1U);
}

BOOST_AUTO_TEST_CASE(pq_payment_root_gate_starts_after_finality_anchor)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        int dip3_height{consensus.DIP0003Height};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int legacy_anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_anchor_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn_state{consensus.hashPQLegacyMNState};
        uint256 legacy_pq_state{consensus.hashPQLegacyPQRegistryState};
        int finality_anchor_height{consensus.nPQChainLockAnchorHeight};
        uint256 finality_anchor_block{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            consensus.DIP0003Height = dip3_height;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = legacy_anchor_height;
            consensus.hashPQLegacyAnchorBlock = legacy_anchor_block;
            consensus.hashPQLegacyMNState = legacy_mn_state;
            consensus.hashPQLegacyPQRegistryState = legacy_pq_state;
            consensus.nPQChainLockAnchorHeight = finality_anchor_height;
            consensus.hashPQChainLockAnchorBlock = finality_anchor_block;
        }
    } restore{consensus};

    constexpr int preparation_height{1295};
    constexpr int epoch_origin{1440};
    constexpr int finality_anchor_height{1440};
    consensus.DIP0003Height = preparation_height - 1;
    consensus.nPQPreparationHeight = preparation_height;
    consensus.nPQChainLockEpochOrigin = epoch_origin;
    consensus.nPQRegistrationCutoffBlocks = 144;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQLegacyAnchorBlock.SetNull();
    consensus.hashPQLegacyMNState.SetNull();
    consensus.hashPQLegacyPQRegistryState.SetNull();
    consensus.nPQChainLockAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQChainLockAnchorBlock.SetNull();

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);

    auto db_params = DBParams{
        .path = "testdb_dmn_pq_payment_root_gate",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const uint256 base_hash{MakeSnapshotKey(preparation_height - 1)};
    CDeterministicMNList base_list{
        base_hash, preparation_height - 1, 1};
    base_list.AddMN(MakeLegacyReplayMN(0, 20),
                    /*fBumpTotalCount=*/false);
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        base_hash, base_list, /*fSync=*/true));

    constexpr int block_count{
        finality_anchor_height - preparation_height + 1};
    std::vector<CBlock> blocks(static_cast<size_t>(block_count));
    std::vector<uint256> hashes(static_cast<size_t>(block_count));
    std::vector<CBlockIndex> indices(static_cast<size_t>(block_count));
    CBlockIndex base_index;
    base_index.nHeight = preparation_height - 1;
    base_index.phashBlock = &base_hash;
    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;

    for (int offset{0}; offset < block_count; ++offset) {
        const int height{preparation_height + offset};
        auto& block{blocks[static_cast<size_t>(offset)]};
        block = MakeProviderMutationBlock({});
        block.hashPrevBlock = offset == 0
            ? base_hash
            : hashes[static_cast<size_t>(offset - 1)];
        block.nTime = static_cast<uint32_t>(height);
        block.nNonce = static_cast<uint32_t>(height);
        hashes[static_cast<size_t>(offset)] = block.GetHash();

        auto& index{indices[static_cast<size_t>(offset)]};
        index.nHeight = height;
        index.pprev = offset == 0
            ? &base_index
            : &indices[static_cast<size_t>(offset - 1)];
        index.phashBlock = &hashes[static_cast<size_t>(offset)];

        BlockValidationState state;
        CDeterministicMNListNEVMAddressDiff diff;
        BOOST_REQUIRE_MESSAGE(manager.ProcessBlock(
            block, &index, state, view, no_legacy_commitment, diff,
            /*fJustCheck=*/false, /*ibd=*/true), state.ToString());
    }

    consensus.nPQLegacyAnchorHeight = preparation_height;
    consensus.hashPQLegacyAnchorBlock = MakeSnapshotKey(70'000);
    consensus.hashPQLegacyMNState = MakeSnapshotKey(70'001);
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(70'002);
    consensus.nPQChainLockAnchorHeight = finality_anchor_height;
    consensus.hashPQChainLockAnchorBlock = hashes.back();

    // SYSCOIN: The projection path must apply the same empty root-capable set
    // as exact consensus selection instead of falling back to rootless MNs.
    std::vector<CDeterministicMNCPtr> projected_payees;
    BOOST_REQUIRE(manager.GetProjectedMNPayeesForBlock(
        &indices.back(), 20, projected_payees));
    BOOST_CHECK(projected_payees.empty());

    CDeterministicMNList current;
    CDeterministicMNList previous;
    BlockValidationState at_anchor_state;
    BOOST_REQUIRE(manager.BuildNewListFromBlock(
        blocks.back(), indices.back().pprev, at_anchor_state, view,
        current, previous, no_legacy_commitment));

    CBlock post_anchor_block{MakeProviderMutationBlock({})};
    post_anchor_block.hashPrevBlock = hashes.back();
    post_anchor_block.nTime = finality_anchor_height + 1;
    post_anchor_block.nNonce = finality_anchor_height + 1;
    BlockValidationState post_anchor_state;
    BOOST_CHECK(!manager.BuildNewListFromBlock(
        post_anchor_block, &indices.back(), post_anchor_state, view,
        current, previous, no_legacy_commitment));
    BOOST_CHECK(post_anchor_state.IsInvalid());
    BOOST_CHECK_EQUAL(post_anchor_state.GetRejectReason(),
                      "bad-pq-no-payment-eligible-mn");
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

BOOST_AUTO_TEST_CASE(inverse_diff_round_trip_restores_all_mutation_kinds)
{
    CDataStream oversized_diff{SER_DISK, PROTOCOL_VERSION};
    WriteCompactSize(
        oversized_diff, CDeterministicMNListDiff::MAX_CHANGES + 1);
    CDeterministicMNListDiff rejected_diff;
    BOOST_CHECK_THROW(oversized_diff >> rejected_diff,
                      std::ios_base::failure);

    const uint256 genesis_hash{MakeSnapshotKey(60'000)};
    const uint256 parent_hash{MakeSnapshotKey(60'001)};
    const uint256 child_hash{MakeSnapshotKey(60'002)};
    constexpr int parent_height{4321};
    CDeterministicMNList parent{
        MakeNontrivialAnchorSnapshot(parent_hash, parent_height, false)};
    const uint256 parent_state_hash{
        parent.GetPQLegacyStateHash(genesis_hash)};

    CDeterministicMNList child{parent};
    child.ResetTrackedChanges();
    child.SetBlockHash(child_hash);
    child.SetHeight(parent_height + 1);

    const auto removed{parent.GetMNByInternalId(9)};
    BOOST_REQUIRE(removed);
    child.RemoveMN(removed->proTxHash);

    const auto added{MakeAnchorMN(17, 4)};
    child.AddMN(added);

    const auto updated_before{parent.GetMNByInternalId(2)};
    BOOST_REQUIRE(updated_before);
    auto updated_state{
        std::make_shared<CDeterministicMNState>(*updated_before->pdmnState)};
    updated_state->nLastPaidHeight += 77;
    updated_state->nPoSePenalty += 5;
    // The child validly takes a unique property freed by the removal. The
    // inverse must release it from this node before restoring the removed
    // parent node, independent of unordered update iteration.
    updated_state->vchNEVMAddress = removed->pdmnState->vchNEVMAddress;
    child.UpdateMN(updated_before->proTxHash, updated_state);

    CDeterministicMNListDiff inverse;
    child.BuildTrackedInverseDiff(parent, inverse);
    BOOST_REQUIRE_EQUAL(inverse.addedMNs.size(), 1U);
    BOOST_REQUIRE_EQUAL(inverse.updatedMNs.size(), 1U);
    BOOST_REQUIRE_EQUAL(inverse.removedMns.size(), 1U);

    CDataStream encoded{SER_DISK, PROTOCOL_VERSION};
    encoded << inverse;
    CDeterministicMNListDiff decoded;
    encoded >> decoded;

    CBlockIndex parent_index;
    parent_index.nHeight = parent_height;
    parent_index.phashBlock = &parent_hash;
    const CDeterministicMNList recovered{child.ApplyDiff(
        &parent_index, decoded, parent.GetTotalRegisteredCount())};

    BOOST_CHECK_EQUAL(recovered.GetAllMNsCount(), parent.GetAllMNsCount());
    BOOST_CHECK_EQUAL(recovered.GetTotalRegisteredCount(),
                      parent.GetTotalRegisteredCount());
    BOOST_CHECK(recovered.GetPQLegacyStateHash(genesis_hash) ==
                parent_state_hash);
    CDataStream encoded_parent{SER_DISK, PROTOCOL_VERSION};
    CDataStream encoded_recovered{SER_DISK, PROTOCOL_VERSION};
    encoded_parent << parent;
    encoded_recovered << recovered;
    BOOST_REQUIRE_EQUAL(encoded_recovered.size(), encoded_parent.size());
    BOOST_CHECK(std::equal(encoded_recovered.begin(),
                           encoded_recovered.end(),
                           encoded_parent.begin()));
    parent.ForEachMN(false, [&recovered](const CDeterministicMN& expected) {
        const auto actual{recovered.GetMN(expected.proTxHash)};
        BOOST_REQUIRE(actual);
        BOOST_CHECK_EQUAL(actual->GetInternalId(), expected.GetInternalId());
        BOOST_REQUIRE(recovered.GetMNByInternalId(expected.GetInternalId()));
        BOOST_CHECK(recovered.GetMNByInternalId(expected.GetInternalId())
                        ->proTxHash == expected.proTxHash);
        const auto by_collateral{
            recovered.GetUniquePropertyMN(expected.collateralOutpoint)};
        BOOST_REQUIRE(by_collateral);
        BOOST_CHECK(by_collateral->proTxHash == expected.proTxHash);
        const auto by_owner{
            recovered.GetUniquePropertyMN(expected.pdmnState->keyIDOwner)};
        BOOST_REQUIRE(by_owner);
        BOOST_CHECK(by_owner->proTxHash == expected.proTxHash);
    });
    BOOST_CHECK(!recovered.HasMN(added->proTxHash));
}

BOOST_AUTO_TEST_CASE(tracked_net_removals_follow_final_membership)
{
    const auto member{MakeAnchorMN(1, 1)};
    CDeterministicMNList parent{MakeSnapshotKey(60'010), 4'330, 1};
    parent.AddMN(member, /*fBumpTotalCount=*/false);

    auto update_only{parent};
    update_only.ResetTrackedChanges();
    auto updated_state{
        std::make_shared<CDeterministicMNState>(*member->pdmnState)};
    ++updated_state->nLastPaidHeight;
    update_only.UpdateMN(member->proTxHash, updated_state);
    BOOST_CHECK(
        update_only.BuildTrackedNetRemovedProTxHashes(parent).empty());

    auto failed_mutation{parent};
    failed_mutation.ResetTrackedChanges();
    BOOST_CHECK_THROW(
        failed_mutation.RemoveMN(MakeSnapshotKey(60'099)),
        std::runtime_error);
    BOOST_CHECK_EQUAL(failed_mutation.TrackedChangeCountForTesting(), 0U);
    BOOST_CHECK(
        failed_mutation.BuildTrackedNetRemovedProTxHashes(parent).empty());

    auto removed{parent};
    removed.ResetTrackedChanges();
    removed.RemoveMN(member->proTxHash);
    const auto parent_removal{
        removed.BuildTrackedNetRemovedProTxHashes(parent)};
    BOOST_REQUIRE_EQUAL(parent_removal.size(), 1U);
    BOOST_CHECK(parent_removal.front() == member->proTxHash);

    auto transient_add{parent};
    transient_add.ResetTrackedChanges();
    const auto transient{MakeAnchorMN(2, 2)};
    transient_add.AddMN(transient, /*fBumpTotalCount=*/false);
    transient_add.RemoveMN(transient->proTxHash);
    BOOST_CHECK(
        transient_add.BuildTrackedNetRemovedProTxHashes(parent).empty());

    auto restored{parent};
    restored.ResetTrackedChanges();
    restored.RemoveMN(member->proTxHash);
    restored.AddMN(member, /*fBumpTotalCount=*/false);
    BOOST_CHECK(restored.BuildTrackedNetRemovedProTxHashes(parent).empty());

    auto updated_then_removed{parent};
    updated_then_removed.ResetTrackedChanges();
    updated_then_removed.UpdateMN(member->proTxHash, updated_state);
    updated_then_removed.RemoveMN(member->proTxHash);
    const auto updated_removal{
        updated_then_removed.BuildTrackedNetRemovedProTxHashes(parent)};
    BOOST_REQUIRE_EQUAL(updated_removal.size(), 1U);
    BOOST_CHECK(updated_removal.front() == member->proTxHash);
}

BOOST_AUTO_TEST_CASE(tracked_net_removals_are_sorted_unique_and_cover_collateral_replacement)
{
    const auto first{MakeAnchorMN(3, 3)};
    const auto second{MakeAnchorMN(4, 20)};
    const auto replaced{MakeAnchorMN(5, 11)};
    CDeterministicMNList parent{MakeSnapshotKey(60'011), 4'331, 3};
    parent.AddMN(first, /*fBumpTotalCount=*/false);
    parent.AddMN(second, /*fBumpTotalCount=*/false);
    parent.AddMN(replaced, /*fBumpTotalCount=*/false);

    auto child{parent};
    child.ResetTrackedChanges();
    child.RemoveMN(second->proTxHash);
    child.RemoveMN(replaced->proTxHash);
    auto first_state{
        std::make_shared<CDeterministicMNState>(*first->pdmnState)};
    ++first_state->nPoSePenalty;
    child.UpdateMN(first->proTxHash, first_state);
    child.RemoveMN(first->proTxHash);

    const auto replacement_source{MakeAnchorMN(6, 12)};
    auto replacement{std::make_shared<CDeterministicMN>(
        replacement_source->GetInternalId())};
    replacement->proTxHash = replacement_source->proTxHash;
    replacement->collateralOutpoint = replaced->collateralOutpoint;
    replacement->nOperatorReward = replacement_source->nOperatorReward;
    replacement->pdmnState = replacement_source->pdmnState;
    child.AddMN(replacement, /*fBumpTotalCount=*/false);

    std::vector<uint256> expected{
        first->proTxHash, second->proTxHash, replaced->proTxHash};
    std::sort(expected.begin(), expected.end());
    const auto removals{child.BuildTrackedNetRemovedProTxHashes(parent)};
    BOOST_CHECK(removals == expected);
    BOOST_CHECK(std::adjacent_find(removals.begin(), removals.end()) ==
                removals.end());
    BOOST_REQUIRE(child.HasMN(replacement->proTxHash));
    BOOST_CHECK(child.GetMN(replacement->proTxHash)->collateralOutpoint ==
                replaced->collateralOutpoint);
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

    manager.FailNextInverseJournalFlushForTesting();
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/false));
    BOOST_CHECK_THROW(
        manager.FlushPendingSnapshotsToDisk(/*fSync=*/true),
        dbwrapper_error);
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));

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

BOOST_AUTO_TEST_CASE(snapshot_compaction_is_bounded_and_resumes_after_restart)
{
    SelectParams(ChainType::MAIN);
    constexpr int stale_backlog{
        2 * static_cast<int>(
                CDeterministicMNManager::
                    SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS) +
        17};
    const int cache_limit{CDeterministicMNManager::LIST_CACHE_SIZE};
    const int start_height{Params().GetConsensus().DIP0003Height};
    const int total_snapshots{cache_limit + stale_backlog};
    const auto chain{
        BuildSnapshotIndexChain(start_height, total_snapshots)};
    const ScopedDiskDBPath disk_db;
    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };

    {
        CDeterministicMNManager manager(db_params);
        manager.UpdatedBlockTip(chain.Tip());
        constexpr int flush_chunk{256};
        for (int offset{0}; offset < total_snapshots;
             offset += flush_chunk) {
            const int count{
                std::min(flush_chunk, total_snapshots - offset)};
            WriteSnapshotRange(manager, start_height + offset, count);
            BOOST_REQUIRE(
                manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
        }
        BOOST_REQUIRE_EQUAL(
            manager.m_evoDb->CountPersistedEntries(), total_snapshots);

        BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
        BOOST_CHECK(!manager.HasPersistentWindow());
        BOOST_CHECK_EQUAL(
            manager.m_evoDb->CountPersistedEntries(),
            total_snapshots - static_cast<int>(
                CDeterministicMNManager::
                    SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS));
    }

    // The cursor is deliberately process-local. A restart safely rescans
    // already-compacted keys and still applies only one bounded erase batch.
    db_params.wipe_data = false;
    CDeterministicMNManager restarted(db_params);
    restarted.UpdatedBlockTip(chain.Tip());
    int64_t previous_count{
        restarted.m_evoDb->CountPersistedEntries()};
    BOOST_REQUIRE(restarted.FlushCacheToDisk(/*bForceFlush=*/true));
    int64_t current_count{restarted.m_evoDb->CountPersistedEntries()};
    BOOST_CHECK_LE(
        previous_count - current_count,
        static_cast<int64_t>(
            CDeterministicMNManager::
                SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS));
    BOOST_CHECK(!restarted.HasPersistentWindow());

    previous_count = current_count;
    BOOST_REQUIRE(restarted.FlushCacheToDisk(/*bForceFlush=*/true));
    current_count = restarted.m_evoDb->CountPersistedEntries();
    BOOST_CHECK_LE(
        previous_count - current_count,
        static_cast<int64_t>(
            CDeterministicMNManager::
                SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS));
    BOOST_CHECK(restarted.HasPersistentWindow());
    BOOST_CHECK_EQUAL(current_count, cache_limit);
}

BOOST_AUTO_TEST_CASE(snapshot_compaction_progresses_across_moving_tips)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit{CDeterministicMNManager::LIST_CACHE_SIZE};
    const int start_height{Params().GetConsensus().DIP0003Height};
    constexpr int stale_count{300};
    std::array<SnapshotIndexChain, 5> branches;
    for (size_t branch{0}; branch < branches.size(); ++branch) {
        branches[branch] = BuildSnapshotIndexChain(
            start_height, cache_limit + (branch == 0 ? 1 : 0));
        for (size_t offset{0}; offset < branches[branch].hashes.size();
             ++offset) {
            branches[branch].hashes[offset] = MakeOrderedSnapshotKey(
                static_cast<uint8_t>(0x10 + branch), offset);
        }
    }

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_moving_tip_compaction",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    const CBlockIndex* first_tip{
        branches[0].At(start_height + cache_limit - 1)};
    manager.UpdatedBlockTip(first_tip);

    size_t pending{0};
    const auto persist = [&](const uint256& hash, int height) {
        manager.m_evoDb->WriteCache(
            hash, CDeterministicMNList{hash, height, 0});
        if (++pending == 256) {
            BOOST_REQUIRE(
                manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
            pending = 0;
        }
    };
    for (size_t branch{0}; branch < branches.size(); ++branch) {
        for (int offset{0}; offset < cache_limit; ++offset) {
            persist(branches[branch].hashes[offset],
                    start_height + offset);
        }
    }
    std::array<uint256, stale_count> stale_hashes;
    for (size_t offset{0}; offset < stale_hashes.size(); ++offset) {
        stale_hashes[offset] = MakeOrderedSnapshotKey(0xe0, offset);
        persist(stale_hashes[offset], start_height);
    }
    if (pending != 0) {
        BOOST_REQUIRE(
            manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
    }

    const std::array<const CBlockIndex*, 4> recovery{
        branches[1].Tip(), branches[2].Tip(), branches[3].Tip(),
        branches[4].Tip()};
    const int64_t initial_count{
        static_cast<int64_t>(branches.size()) * cache_limit + stale_count};
    BOOST_REQUIRE_EQUAL(
        manager.m_evoDb->CountPersistedEntries(), initial_count);
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false, recovery));
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->CountPersistedEntries(),
        initial_count - static_cast<int64_t>(
                            CDeterministicMNManager::
                                SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS));
    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(stale_hashes.front(), snapshot));
    BOOST_CHECK(!manager.HasPersistentWindow());

    // A normal tip insertion changes one retained key but must not reset or
    // starve snapshot compaction behind the five production branch windows.
    const CBlockIndex* advanced_tip{branches[0].Tip()};
    const uint256 advanced_hash{advanced_tip->GetBlockHash()};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        advanced_hash,
        CDeterministicMNList{
            advanced_hash, advanced_tip->nHeight, 0},
        /*fSync=*/true));
    manager.UpdatedBlockTip(advanced_tip);
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false, recovery));
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->CountPersistedEntries(),
        static_cast<int64_t>(branches.size()) * cache_limit);
    BOOST_CHECK(manager.HasPersistentWindow());
    BOOST_CHECK(!manager.m_evoDb->Read(
        branches[0].hashes.front(), snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(advanced_hash, snapshot));

    // Production supplies no more than four distinct recovery heads. Reject
    // a structurally impossible caller instead of weakening the visit proof.
    const std::array<const CBlockIndex*, 5> excessive_recovery{
        advanced_tip, branches[1].Tip(), branches[2].Tip(),
        branches[3].Tip(), branches[4].Tip()};
    BOOST_CHECK(!manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false, excessive_recovery));
}

BOOST_AUTO_TEST_CASE(snapshot_compaction_restarts_when_finality_floor_advances)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit{CDeterministicMNManager::LIST_CACHE_SIZE};
    const int start_height{Params().GetConsensus().DIP0003Height};
    auto chain{BuildSnapshotIndexChain(start_height, cache_limit)};
    for (size_t offset{0}; offset < chain.hashes.size(); ++offset) {
        chain.hashes[offset] = MakeOrderedSnapshotKey(0xf0, offset);
    }
    const int side_height{chain.Tip()->nHeight - 1};
    constexpr size_t side_count{
        CDeterministicMNManager::
            SNAPSHOT_GC_MAX_SCANNED_RECORDS_PER_PASS + 1};

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_finality_floor_cursor",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.UpdatedBlockTip(chain.Tip());
    size_t pending{0};
    const auto persist = [&](const uint256& hash, int height) {
        manager.m_evoDb->WriteCache(
            hash, CDeterministicMNList{hash, height, 0});
        if (++pending == 256) {
            BOOST_REQUIRE(
                manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
            pending = 0;
        }
    };
    for (size_t offset{0}; offset < chain.hashes.size(); ++offset) {
        persist(chain.hashes[offset], start_height + offset);
    }
    std::vector<uint256> side_hashes;
    side_hashes.reserve(side_count);
    for (size_t offset{0}; offset < side_count; ++offset) {
        side_hashes.emplace_back(MakeOrderedSnapshotKey(0x10, offset));
        persist(side_hashes.back(), side_height);
    }
    if (pending != 0) {
        BOOST_REQUIRE(
            manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
    }

    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(side_height),
        side_height);
    const int64_t initial_count{
        static_cast<int64_t>(cache_limit + side_count)};
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->CountPersistedEntries(), initial_count);
    BOOST_CHECK(!manager.HasPersistentWindow());

    // Raising the floor makes every previously visited side snapshot
    // deletable. The old cursor must be discarded so the next bounded pass
    // reconsiders the already-scanned prefix immediately.
    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(side_height + 1),
        side_height + 1);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK_EQUAL(
        manager.m_evoDb->CountPersistedEntries(),
        initial_count - static_cast<int64_t>(
                            CDeterministicMNManager::
                                SNAPSHOT_GC_MAX_ERASE_ITEMS_PER_PASS));
    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(side_hashes.front(), snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(side_hashes.back(), snapshot));
}

BOOST_AUTO_TEST_CASE(maintenance_retains_all_chainstate_recovery_snapshots)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit = CDeterministicMNManager::LIST_CACHE_SIZE;
    const int start_height = Params().GetConsensus().DIP0003Height;
    const int total_snapshots = cache_limit + 8;

    auto db_params = DBParams{
        .path = "testdb_dmn_durable_coins_recovery",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto chain = BuildSnapshotIndexChain(start_height, total_snapshots);
    manager.UpdatedBlockTip(chain.Tip());
    const uint256 durable_hash{MakeSnapshotKey(start_height)};
    const uint256 prospective_hash{MakeSnapshotKey(start_height + 1)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        durable_hash, MakeSnapshot(start_height), /*fSync=*/true));
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        prospective_hash, MakeSnapshot(start_height + 1),
        /*fSync=*/true));
    WriteSnapshotRange(manager, start_height + 2, total_snapshots - 2);

    const std::array<const CBlockIndex*, 3> recovery_indexes{
        chain.At(start_height), chain.At(start_height + 1),
        chain.At(start_height)};
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false, recovery_indexes));

    CDeterministicMNList snapshot;
    BOOST_REQUIRE(manager.m_evoDb->Read(durable_hash, snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height);
    BOOST_REQUIRE(manager.m_evoDb->Read(prospective_hash, snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), start_height + 1);
    BOOST_CHECK(!manager.m_evoDb->Read(MakeSnapshotKey(start_height + 2),
                                       snapshot));
    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(),
                      cache_limit + 2);

    // Once every chainstate advances, same-tip maintenance must reconsider
    // both old recovery snapshots rather than taking its normal no-op path.
    const std::array<const CBlockIndex*, 1> advanced_recovery{
        chain.Tip()};
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false,
        advanced_recovery));
    BOOST_CHECK(!manager.m_evoDb->Read(durable_hash, snapshot));
    BOOST_CHECK(!manager.m_evoDb->Read(prospective_hash, snapshot));
    BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(), cache_limit);
}

BOOST_AUTO_TEST_CASE(maintenance_retains_each_chainstate_random_access_window)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit{CDeterministicMNManager::LIST_CACHE_SIZE};
    const int start_height{Params().GetConsensus().DIP0003Height};
    const auto active_chain{BuildSnapshotIndexChain(
        start_height, 2 * cache_limit + 17)};
    auto background_chain{BuildSnapshotIndexChain(
        start_height, cache_limit + 6)};
    for (uint256& hash : background_chain.hashes) {
        hash.begin()[31] ^= 0x80;
    }
    const int background_height{start_height + cache_limit + 4};
    const int oldest_retained_height{
        background_height - cache_limit + 1};
    const int representative_ancestor_height{
        background_height - cache_limit / 2};
    const int outside_window_height{background_height - cache_limit};
    BOOST_REQUIRE_GT(active_chain.Tip()->nHeight - background_height,
                     cache_limit);

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_multichain_window",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.UpdatedBlockTip(active_chain.Tip());
    const auto write_snapshot = [&](const CBlockIndex* pindex) {
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            pindex->GetBlockHash(),
            CDeterministicMNList{
                pindex->GetBlockHash(), pindex->nHeight, 0},
            /*fSync=*/true));
    };
    WriteSnapshotRange(
        manager, active_chain.Tip()->nHeight - cache_limit + 1,
        cache_limit);
    for (const int height : {background_height,
                             oldest_retained_height,
                             representative_ancestor_height,
                             outside_window_height}) {
        write_snapshot(background_chain.At(height));
    }

    const std::array<const CBlockIndex*, 2> recovery_indexes{
        active_chain.Tip(), background_chain.At(background_height)};
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false, recovery_indexes));

    const auto oldest_retained{manager.GetListForBlock(
        background_chain.At(oldest_retained_height))};
    BOOST_CHECK_EQUAL(oldest_retained.GetHeight(), oldest_retained_height);
    const auto representative_ancestor{manager.GetListForBlock(
        background_chain.At(representative_ancestor_height))};
    BOOST_CHECK_EQUAL(representative_ancestor.GetHeight(),
                      representative_ancestor_height);
    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(
        background_chain.At(outside_window_height)->GetBlockHash(),
        snapshot));

    // Changing only the background marker must bypass the same-active-tip
    // no-op and reclaim the single ancestor that fell out of its new window.
    const CBlockIndex* advanced_background{
        background_chain.At(background_height + 1)};
    write_snapshot(advanced_background);
    const std::array<const CBlockIndex*, 2> advanced_recovery_indexes{
        active_chain.Tip(), advanced_background};
    BOOST_REQUIRE(manager.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false,
        advanced_recovery_indexes));
    BOOST_CHECK(!manager.m_evoDb->Read(
        background_chain.At(oldest_retained_height)->GetBlockHash(),
        snapshot));
    BOOST_REQUIRE(manager.VerifyPersistedSnapshot(advanced_background));
    BOOST_CHECK_EQUAL(
        manager.GetListForBlock(
                   background_chain.At(representative_ancestor_height))
            .GetHeight(),
        representative_ancestor_height);
}

BOOST_AUTO_TEST_CASE(auxiliary_history_retention_plan_separates_authority)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreAnchors {
        Consensus::Params& consensus;
        int chainlock_height{consensus.nPQChainLockAnchorHeight};
        uint256 chainlock_hash{consensus.hashPQChainLockAnchorBlock};
        int legacy_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_hash{consensus.hashPQLegacyAnchorBlock};
        ~RestoreAnchors()
        {
            consensus.nPQChainLockAnchorHeight = chainlock_height;
            consensus.hashPQChainLockAnchorBlock = chainlock_hash;
            consensus.nPQLegacyAnchorHeight = legacy_height;
            consensus.hashPQLegacyAnchorBlock = legacy_hash;
        }
    } restore{consensus};

    const int start_height{consensus.DIP0003Height};
    auto active_chain{BuildSnapshotIndexChain(start_height, 24)};
    auto recovery_chain{BuildSnapshotIndexChain(start_height, 17)};
    const int anchor_height{start_height + 5};
    for (int height{anchor_height + 1};
         height <= recovery_chain.Tip()->nHeight; ++height) {
        recovery_chain.hashes[height - start_height].begin()[31] ^= 0x80;
    }
    consensus.nPQChainLockAnchorHeight = anchor_height;
    consensus.hashPQChainLockAnchorBlock =
        active_chain.At(anchor_height)->GetBlockHash();
    consensus.nPQLegacyAnchorHeight = start_height + 2;
    consensus.hashPQLegacyAnchorBlock =
        active_chain.At(consensus.nPQLegacyAnchorHeight)->GetBlockHash();

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_auxiliary_retention_plan",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.UpdatedBlockTip(active_chain.Tip());
    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(start_height + 1),
        start_height + 1);
    const std::array<const CBlockIndex*, 1> recovery{
        recovery_chain.Tip()};

    auto plan{manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery)};
    BOOST_CHECK(plan.requirements_valid);
    BOOST_CHECK(plan.finality_health_ambiguous);
    BOOST_CHECK(!plan.destructive_authorization);
    BOOST_CHECK(!plan.AllowsDestructiveGC());
    BOOST_REQUIRE_EQUAL(plan.branches.size(), 2U);
    BOOST_CHECK(plan.branches.front().active);
    BOOST_CHECK_EQUAL(plan.branches.front().snapshot_window.size(), 24U);
    BOOST_CHECK(!plan.branches.back().active);
    BOOST_CHECK_EQUAL(plan.branches.back().snapshot_window.size(), 17U);
    BOOST_REQUIRE_EQUAL(plan.fixed_dependencies.size(), 1U);
    BOOST_CHECK_EQUAL(plan.fixed_dependencies.front().height,
                      consensus.nPQLegacyAnchorHeight);

    using Authorization =
        CDeterministicMNManager::AuxiliaryHistoryGCAuthorization;
    using AuthorizationSource = CDeterministicMNManager::
        AuxiliaryHistoryGCAuthorizationSource;
    const Authorization invalid{
        static_cast<AuthorizationSource>(0xff),
        {anchor_height, consensus.hashPQChainLockAnchorBlock}};
    BOOST_CHECK(!manager.UpdateAuxiliaryHistoryGCAuthorization(invalid));
    BOOST_CHECK(!manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery)
                     .destructive_authorization);

    const Authorization anchor{
        AuthorizationSource::IMMUTABLE_CHAINLOCK_ANCHOR,
        {anchor_height, consensus.hashPQChainLockAnchorBlock}};
    manager.UpdateFinalitySnapshotPublicationRetention(true);
    BOOST_REQUIRE(manager.UpdateAuxiliaryHistoryGCAuthorization(
        anchor, /*release_publication=*/true));
    plan = manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery);
    BOOST_CHECK(!plan.finality_publication_pending);
    BOOST_CHECK(!plan.finality_health_ambiguous);
    BOOST_CHECK(plan.AllowsDestructiveGC());

    BOOST_CHECK_EQUAL(
        manager.UpdateReplaySnapshotRetentionFloor(start_height),
        start_height);
    plan = manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery);
    BOOST_CHECK(plan.replay_floor);
    BOOST_CHECK(!plan.AllowsDestructiveGC());
    manager.UpdateReplaySnapshotRetentionFloor(std::nullopt);

    manager.BeginFinalitySnapshotVerificationRetention();
    plan = manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery);
    BOOST_CHECK(plan.finality_verification_active);
    BOOST_CHECK(!plan.AllowsDestructiveGC());
    manager.EndFinalitySnapshotVerificationRetention();

    const int winner_height{anchor_height + 5};
    const Authorization winner{
        AuthorizationSource::ENFORCED_DURABLE_CHAINLOCK,
        {winner_height,
         active_chain.At(winner_height)->GetBlockHash()}};
    BOOST_REQUIRE(
        manager.UpdateAuxiliaryHistoryGCAuthorization(winner));

    // A crash can leave the recovered UTXO tip behind the fsynced GC
    // authorizer. Startup accepts only a directly comparable indexed
    // descendant and keeps the actual recovered tip as the retention head.
    const CBlockIndex* winner_index{active_chain.At(winner_height)};
    const auto lookup_winner = [&](const uint256& hash) {
        return hash == winner_index->GetBlockHash()
            ? winner_index
            : nullptr;
    };
    const CBlockIndex* recovered_tip{active_chain.At(winner_height - 1)};
    BOOST_REQUIRE(manager.UpdatedBlockTipForStartup(
        recovered_tip, lookup_winner));
    plan = manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery);
    BOOST_REQUIRE(!plan.branches.empty());
    BOOST_CHECK(plan.branches.front().head.block_hash ==
                recovered_tip->GetBlockHash());
    BOOST_CHECK(plan.finality_health_ambiguous);
    BOOST_CHECK(!manager.UpdatedBlockTipForStartup(
        recovery_chain.At(winner_height - 1), lookup_winner));
    manager.UpdatedBlockTip(active_chain.Tip());

    BOOST_REQUIRE(
        manager.UpdateAuxiliaryHistoryGCAuthorization(std::nullopt));
    BOOST_CHECK(!manager.UpdateAuxiliaryHistoryGCAuthorization(anchor));
    plan = manager.GetAuxiliaryHistoryRetentionPlanForTesting(recovery);
    BOOST_CHECK(!plan.destructive_authorization);
    BOOST_CHECK(plan.finality_health_ambiguous);
    BOOST_CHECK(!plan.AllowsDestructiveGC());
}

BOOST_AUTO_TEST_CASE(
    pq_gc_startup_binds_descendant_authorizer_before_preparation)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreProfile {
        Consensus::Params& consensus;
        int dip3{consensus.DIP0003Height};
        int preparation{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int legacy_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn{consensus.hashPQLegacyMNState};
        uint256 legacy_pq{consensus.hashPQLegacyPQRegistryState};
        int chainlock_height{consensus.nPQChainLockAnchorHeight};
        uint256 chainlock_block{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            consensus.DIP0003Height = dip3;
            consensus.nPQPreparationHeight = preparation;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = legacy_height;
            consensus.hashPQLegacyAnchorBlock = legacy_block;
            consensus.hashPQLegacyMNState = legacy_mn;
            consensus.hashPQLegacyPQRegistryState = legacy_pq;
            consensus.nPQChainLockAnchorHeight = chainlock_height;
            consensus.hashPQChainLockAnchorBlock = chainlock_block;
        }
    } restore{consensus};

    constexpr int dip3_height{1290};
    constexpr int boundary_height{dip3_height + 1};
    constexpr int recovered_height{dip3_height + 2};
    constexpr int preparation_height{dip3_height + 3};
    constexpr int anchor_height{dip3_height + 4};
    constexpr int authorizer_height{dip3_height + 5};
    auto chain{BuildSnapshotIndexChain(
        dip3_height, authorizer_height - dip3_height + 1)};

    consensus.DIP0003Height = dip3_height;
    consensus.nPQPreparationHeight = preparation_height;
    consensus.nPQChainLockEpochOrigin = 1440;
    consensus.nPQRegistrationCutoffBlocks = 144;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQLegacyAnchorHeight = anchor_height;
    consensus.hashPQLegacyAnchorBlock =
        chain.At(anchor_height)->GetBlockHash();
    consensus.hashPQLegacyMNState = MakeSnapshotKey(96'001);
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(96'002);
    consensus.nPQChainLockAnchorHeight = anchor_height;
    consensus.hashPQChainLockAnchorBlock =
        consensus.hashPQLegacyAnchorBlock;
    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);
    BOOST_REQUIRE(Consensus::CheckPQChainLockAnchorConfiguration(
                      consensus) == Consensus::PQAnchorResult::VALID);

    const ScopedDiskDBPath disk_db;
    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    using Authorization =
        CDeterministicMNManager::AuxiliaryHistoryGCAuthorization;
    const Authorization authorization{
        evo::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {authorizer_height,
         chain.At(authorizer_height)->GetBlockHash()}};

    {
        CDeterministicMNManager builder(db_params);
        BOOST_REQUIRE(builder.UpdateAuxiliaryHistoryGCAuthorization(
            authorization));
        evo::DMNInverseGCClosure closure;
        closure.boundary = {
            boundary_height,
            chain.At(boundary_height)->GetBlockHash()};
        closure.boundary_state_hash = MakeSnapshotKey(96'003);
        closure.inverse_history_commitment = MakeSnapshotKey(96'004);
        closure.inverse_record_hash = MakeSnapshotKey(96'005);
        const auto payload{evo::EncodeDMNInverseGCClosure(closure)};
        BOOST_REQUIRE(payload);
        evo::AuxiliaryHistoryGCIntentTarget target;
        target.authorization = authorization;
        target.frontier.dmn = evo::AuxiliaryHistoryGCComponent{
            evo::DMNInverseGCClosure::VERSION,
            static_cast<uint64_t>(boundary_height), *payload};
        BOOST_REQUIRE(builder.BeginAuxiliaryHistoryGCIntentForTesting(
            target));
    }

    db_params.wipe_data = false;
    CDeterministicMNManager restarted(db_params);
    const CBlockIndex* authorizer{chain.At(authorizer_height)};
    const auto lookup_authorizer = [&](const uint256& hash) {
        return hash == authorizer->GetBlockHash() ? authorizer : nullptr;
    };
    uint256 fork_hash{MakeSnapshotKey(96'006)};
    CBlockIndex fork_recovered;
    fork_recovered.nHeight = recovered_height;
    fork_recovered.pprev = chain.At(boundary_height);
    fork_recovered.phashBlock = &fork_hash;
    BOOST_CHECK(!restarted.UpdatedBlockTipForStartup(
        &fork_recovered, lookup_authorizer));

    const CBlockIndex* recovered{chain.At(recovered_height)};
    BOOST_REQUIRE(restarted.UpdatedBlockTipForStartup(
        recovered, lookup_authorizer));
    BOOST_CHECK(restarted.VerifyPersistedPQRegistrySnapshot(recovered));
    restarted.UpdatedBlockTip(recovered);
    BOOST_CHECK_NO_THROW(
        restarted.FailNextPQRegistryWriteThroughForTesting());
    BOOST_CHECK(restarted.VerifyPersistedPQRegistrySnapshot(recovered));
}

BOOST_AUTO_TEST_CASE(
    pq_gc_startup_authenticates_tip_paths_and_below_floor_legacy_anchor)
{
    SelectParams(ChainType::REGTEST);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreProfile {
        Consensus::Params& consensus;
        int dip3{consensus.DIP0003Height};
        int preparation{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int legacy_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_block{consensus.hashPQLegacyAnchorBlock};
        uint256 legacy_mn{consensus.hashPQLegacyMNState};
        uint256 legacy_pq{consensus.hashPQLegacyPQRegistryState};
        int chainlock_height{consensus.nPQChainLockAnchorHeight};
        uint256 chainlock_block{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            consensus.DIP0003Height = dip3;
            consensus.nPQPreparationHeight = preparation;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = legacy_height;
            consensus.hashPQLegacyAnchorBlock = legacy_block;
            consensus.hashPQLegacyMNState = legacy_mn;
            consensus.hashPQLegacyPQRegistryState = legacy_pq;
            consensus.nPQChainLockAnchorHeight = chainlock_height;
            consensus.hashPQChainLockAnchorBlock = chainlock_block;
        }
    } restore{consensus};

    constexpr int preparation_height{1295};
    constexpr int anchor_height{preparation_height + 17};
    constexpr int checkpoint_height{
        preparation_height + llmq::pq::PQ_REGISTRY_CHECKPOINT_INTERVAL};
    constexpr int first_height{preparation_height - 1};
    const int block_count{checkpoint_height - preparation_height + 2};

    SnapshotIndexChain chain{
        first_height,
        std::vector<uint256>(block_count + 1),
        std::vector<CBlockIndex>(block_count + 1)};
    std::vector<CBlock> blocks;
    blocks.reserve(block_count);
    chain.hashes.front() = MakeSnapshotKey(120'000);
    chain.indices.front().nHeight = first_height;
    chain.indices.front().phashBlock = &chain.hashes.front();
    for (int i{0}; i < block_count; ++i) {
        const int height{preparation_height + i};
        CBlock block{MakeProviderMutationBlock({})};
        block.hashPrevBlock = chain.hashes[i];
        block.nTime = static_cast<uint32_t>(1'700'000'000 + height);
        block.nNonce = static_cast<uint32_t>(height);
        blocks.push_back(std::move(block));
        chain.hashes[i + 1] = blocks.back().GetHash();
        chain.indices[i + 1].nHeight = height;
        chain.indices[i + 1].pprev = &chain.indices[i];
        chain.indices[i + 1].phashBlock = &chain.hashes[i + 1];
    }

    consensus.DIP0003Height = first_height;
    consensus.nPQPreparationHeight = preparation_height;
    consensus.nPQChainLockEpochOrigin = 1440;
    consensus.nPQRegistrationCutoffBlocks = 144;
    consensus.nPQFutureHorizonEpochs = 8;
    consensus.nPQLegacyAnchorHeight = anchor_height;
    consensus.hashPQLegacyAnchorBlock =
        chain.At(anchor_height)->GetBlockHash();
    const CDeterministicMNList anchor_snapshot{
        consensus.hashPQLegacyAnchorBlock, anchor_height, 0};
    consensus.hashPQLegacyMNState =
        anchor_snapshot.GetPQLegacyStateHash(consensus.hashGenesisBlock);
    const auto empty_pq_root{
        llmq::pq::PQRegistrySnapshot{}.RecomputeConsensusStateRoot(
            consensus.hashGenesisBlock)};
    BOOST_REQUIRE(empty_pq_root);
    consensus.hashPQLegacyPQRegistryState = *empty_pq_root;
    consensus.nPQChainLockAnchorHeight = anchor_height;
    consensus.hashPQChainLockAnchorBlock =
        consensus.hashPQLegacyAnchorBlock;

    llmq::pq::PQRegistryConfig registry_config;
    BOOST_REQUIRE(llmq::pq::GetPQRegistryConfig(
                      consensus, registry_config) ==
                  llmq::pq::PQRegistryDeploymentResult::VALID);
    const ScopedDiskDBPath disk_db;
    DBParams db_params{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = false,
    };
    auto pq_db_params{db_params};
    pq_db_params.path = SiblingDBPath(db_params.path, "_pq_registry");
    pq_db_params.wipe_data = true;
    llmq::pq::PQRegistryCallbacks callbacks;
    callbacks.dmn_exists_before = [](const uint256&) { return false; };
    callbacks.dmn_exists_after = [](const uint256&) { return false; };
    llmq::pq::PQRegistryError registry_error;
    {
        llmq::pq::PQRegistryManager writer{
            pq_db_params, consensus.hashGenesisBlock, registry_config};
        for (int i{0}; i < block_count; ++i) {
            uint256 state_root;
            BOOST_REQUIRE(writer.ProcessBlock(
                blocks[i], preparation_height + i, callbacks, {},
                /*fJustCheck=*/false, registry_error, &state_root));
            if (preparation_height + i == anchor_height) {
                BOOST_CHECK(state_root == *empty_pq_root);
            }
        }
        BOOST_REQUIRE(writer.Flush(/*fSync=*/true));
    }
    pq_db_params.wipe_data = false;

    llmq::pq::PQRegistryGCAuthenticationContext context;
    for (int height{preparation_height}; height <= anchor_height;
         ++height) {
        context.legacy_island.push_back(
            {height, chain.At(height)->GetBlockHash()});
    }
    for (int height{anchor_height}; height <= checkpoint_height;
         ++height) {
        context.rooted_segment.push_back(
            {height, chain.At(height)->GetBlockHash()});
    }
    const llmq::pq::PQRegistryGCRootConfig root_config{
        evo::MakeAuxiliaryHistoryGCDeployment(consensus).configuration_id,
        {anchor_height, consensus.hashPQLegacyAnchorBlock},
        *empty_pq_root};
    evo::AuxiliaryHistoryGCComponent component;
    evo::PQRegistryGCEraseManifest erase_manifest;
    {
        llmq::pq::PQRegistryManager authenticator{
            pq_db_params, consensus.hashGenesisBlock, registry_config,
            root_config};
        BOOST_REQUIRE(authenticator.FlushForGC(registry_error));
        BOOST_REQUIRE(authenticator.BuildGCEraseBatch(
            context, std::nullopt, /*max_scanned_records=*/1,
            llmq::pq::PQ_REGISTRY_GC_MAX_SCANNED_VALUE_BYTES,
            /*max_candidates=*/1, component, erase_manifest,
            registry_error));
    }
    const auto closure{evo::DecodePQRegistryGCClosure(component.closure)};
    BOOST_REQUIRE(closure);
    BOOST_CHECK_EQUAL(closure->scan_complete,
                      evo::PQRegistryGCClosure::SCANNING);
    const auto manifest_payload{
        evo::EncodePQRegistryGCEraseManifest(erase_manifest)};
    BOOST_REQUIRE(manifest_payload);
    evo::AuxiliaryHistoryGCIntentTarget target;
    target.authorization = {
        evo::AuxiliaryHistoryGCAuthorizationSource::
            ENFORCED_DURABLE_CHAINLOCK,
        {checkpoint_height,
         chain.At(checkpoint_height)->GetBlockHash()}};
    target.frontier.pq_registry = component;
    target.pq_erase_manifest = evo::AuxiliaryHistoryGCManifest{
        evo::PQRegistryGCEraseManifest::VERSION, *manifest_payload};

    {
        CDeterministicMNManager builder{db_params};
        BOOST_REQUIRE(builder.m_evoDb->WriteThrough(
            consensus.hashPQLegacyAnchorBlock, anchor_snapshot,
            /*fSync=*/true));
        for (int height{checkpoint_height};
             height <= checkpoint_height + 1; ++height) {
            BOOST_REQUIRE(builder.m_evoDb->WriteThrough(
                chain.At(height)->GetBlockHash(),
                CDeterministicMNList{
                    chain.At(height)->GetBlockHash(), height, 0},
                /*fSync=*/true));
        }
        BOOST_REQUIRE(builder.BeginAuxiliaryHistoryGCIntentForTesting(
            target));
    }

    CDeterministicMNManager restarted{db_params};
    const CBlockIndex* authorizer{chain.At(checkpoint_height)};
    const CBlockIndex* recovered{chain.At(checkpoint_height + 1)};
    const auto lookup_authorizer = [&](const uint256& hash) {
        return hash == authorizer->GetBlockHash() ? authorizer : nullptr;
    };
    BOOST_REQUIRE(restarted.UpdatedBlockTipForStartup(
        recovered, lookup_authorizer));
    const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
        live_authorization{
            evo::AuxiliaryHistoryGCAuthorizationSource::
                ENFORCED_DURABLE_CHAINLOCK,
            {checkpoint_height + 1, recovered->GetBlockHash()}};
    BOOST_REQUIRE(restarted.UpdateAuxiliaryHistoryGCAuthorization(
        live_authorization));
    BOOST_REQUIRE(restarted.VerifyPersistedPQRegistrySnapshot(recovered));
    const auto pending_plan{
        restarted.GetAuxiliaryHistoryRetentionPlanForTesting()};
    BOOST_REQUIRE(pending_plan.requirements_valid);
    BOOST_REQUIRE(pending_plan.effective_pq_registry_gc_boundary);
    BOOST_CHECK(pending_plan.effective_pq_registry_gc_boundary->pending);
    BOOST_CHECK(
        pending_plan.effective_pq_registry_gc_boundary->closure.checkpoint ==
        closure->checkpoint);

    const std::array<const CBlockIndex*, 1> below_checkpoint{
        chain.At(checkpoint_height - 1)};
    BOOST_CHECK(!restarted.GetAuxiliaryHistoryRetentionPlanForTesting(
                              below_checkpoint)
                     .requirements_valid);
    uint256 side_checkpoint_hash{MakeSnapshotKey(120'999)};
    CBlockIndex side_checkpoint;
    side_checkpoint.nHeight = checkpoint_height;
    side_checkpoint.pprev = chain.At(checkpoint_height - 1);
    side_checkpoint.phashBlock = &side_checkpoint_hash;
    const std::array<const CBlockIndex*, 1> side_checkpoint_recovery{
        &side_checkpoint};
    BOOST_CHECK(!restarted.GetAuxiliaryHistoryRetentionPlanForTesting(
                              side_checkpoint_recovery)
                     .requirements_valid);

    // SYSCOIN: A restart resumes the PQ-owned intent before considering new
    // DMN work, installs its logical floor, and completes its exact manifest.
    BOOST_REQUIRE(restarted.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false));
    const auto completed_state{
        restarted.GetAuxiliaryHistoryGCStateForTesting()};
    BOOST_CHECK(!completed_state.intent);
    BOOST_REQUIRE(completed_state.watermark);
    BOOST_CHECK(completed_state.watermark->frontier.pq_registry ==
                target.frontier.pq_registry);
    BOOST_CHECK(completed_state.watermark->authorization ==
                target.authorization);

    // SYSCOIN: Resuming an old-authorizer SCANNING intent cannot set the
    // same-tip marker while a newer live authorizer can continue that exact
    // checkpoint. The follow-up consumes C+1 once, then the unchanged live
    // authorization becomes stable no-work.
    BOOST_REQUIRE(restarted.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false));
    const auto continued_state{
        restarted.GetAuxiliaryHistoryGCStateForTesting()};
    BOOST_CHECK(!continued_state.intent);
    BOOST_REQUIRE(continued_state.watermark);
    BOOST_REQUIRE(continued_state.watermark->frontier.pq_registry);
    const auto continued_closure{evo::DecodePQRegistryGCClosure(
        continued_state.watermark->frontier.pq_registry->closure)};
    BOOST_REQUIRE(continued_closure);
    BOOST_CHECK_EQUAL(continued_closure->generation,
                      closure->generation + 1);
    BOOST_CHECK(continued_closure->checkpoint == closure->checkpoint);
    BOOST_CHECK(continued_state.watermark->authorization ==
                live_authorization);
    BOOST_REQUIRE(restarted.FlushCacheToDisk(
        /*bForceFlush=*/true, /*fSync=*/false));
    const auto stable_state{
        restarted.GetAuxiliaryHistoryGCStateForTesting()};
    BOOST_CHECK(stable_state.intent == continued_state.intent);
    BOOST_CHECK(stable_state.watermark == continued_state.watermark);
    llmq::pq::PQRegistrySnapshot below_floor_snapshot;
    std::string below_floor_error;
    BOOST_CHECK(!restarted.GetPQRegistrySnapshot(
        chain.At(anchor_height), below_floor_snapshot,
        below_floor_error));
    BOOST_CHECK(restarted.VerifyPQLegacyAnchorState(
        chain.At(anchor_height)));
}

BOOST_AUTO_TEST_CASE(dmn_inverse_gc_boundary_uses_only_rollback_inputs)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreAnchors {
        Consensus::Params& consensus;
        int chainlock_height{consensus.nPQChainLockAnchorHeight};
        uint256 chainlock_hash{consensus.hashPQChainLockAnchorBlock};
        int legacy_height{consensus.nPQLegacyAnchorHeight};
        uint256 legacy_hash{consensus.hashPQLegacyAnchorBlock};
        ~RestoreAnchors()
        {
            consensus.nPQChainLockAnchorHeight = chainlock_height;
            consensus.hashPQChainLockAnchorBlock = chainlock_hash;
            consensus.nPQLegacyAnchorHeight = legacy_height;
            consensus.hashPQLegacyAnchorBlock = legacy_hash;
        }
    } restore{consensus};

    const int base{consensus.DIP0003Height};
    const int window{CDeterministicMNManager::LIST_CACHE_SIZE};
    auto active{BuildSnapshotIndexChain(base, 2 * window + 101)};
    consensus.nPQChainLockAnchorHeight = base;
    consensus.hashPQChainLockAnchorBlock =
        active.At(base)->GetBlockHash();
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQLegacyAnchorBlock.SetNull();

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_inverse_gc_boundary",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.UpdatedBlockTip(active.Tip());
    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(base), base);

    using Status = CDeterministicMNManager::DMNInverseGCBoundaryStatus;
    using Authorization =
        CDeterministicMNManager::AuxiliaryHistoryGCAuthorization;
    using Source = CDeterministicMNManager::
        AuxiliaryHistoryGCAuthorizationSource;
    const Authorization anchor{
        Source::IMMUTABLE_CHAINLOCK_ANCHOR,
        {base, active.At(base)->GetBlockHash()}};
    BOOST_REQUIRE(manager.UpdateAuxiliaryHistoryGCAuthorization(anchor));
    auto result{manager.GetDMNInverseGCBoundaryForTesting()};
    BOOST_CHECK(result.status == Status::NO_OP);
    BOOST_REQUIRE(result.boundary);
    BOOST_CHECK_EQUAL(result.boundary->height, base);
    BOOST_CHECK(!result.component);

    const int authorization_height{base + 50};
    const Authorization authorization{
        Source::ENFORCED_DURABLE_CHAINLOCK,
        {authorization_height,
         active.At(authorization_height)->GetBlockHash()}};
    BOOST_REQUIRE(
        manager.UpdateAuxiliaryHistoryGCAuthorization(authorization));
    result = manager.GetDMNInverseGCBoundaryForTesting();
    BOOST_CHECK(result.status == Status::BLOCKED);
    BOOST_REQUIRE(result.boundary);
    BOOST_CHECK_EQUAL(result.boundary->height, authorization_height);

    const Authorization tip_authorization{
        Source::ENFORCED_DURABLE_CHAINLOCK,
        {active.Tip()->nHeight, active.Tip()->GetBlockHash()}};
    BOOST_REQUIRE(
        manager.UpdateAuxiliaryHistoryGCAuthorization(tip_authorization));
    result = manager.GetDMNInverseGCBoundaryForTesting();
    BOOST_CHECK(result.status == Status::BLOCKED);
    BOOST_REQUIRE(result.boundary);
    const int active_floor{active.Tip()->nHeight - window + 1};
    BOOST_CHECK_EQUAL(result.boundary->height, active_floor);

    const int recovery_fork{base + window + 500};
    const int recovery_tip{base + 2 * window};
    auto recovery{BuildForkedSnapshotIndexChain(
        active, recovery_fork, recovery_tip, 0x41)};
    const std::array<const CBlockIndex*, 1> recovery_heads{
        recovery.Tip()};
    result = manager.GetDMNInverseGCBoundaryForTesting(recovery_heads);
    BOOST_CHECK(result.status == Status::BLOCKED);
    BOOST_REQUIRE(result.boundary);
    BOOST_CHECK_EQUAL(
        result.boundary->height, recovery_tip - window + 1);

    // SYSCOIN: A roster snapshot floor is an availability dependency, not a
    // sequential rollback dependency, so moving it cannot move B.
    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(active.Tip()->nHeight),
        active.Tip()->nHeight);
    const auto roster_moved{
        manager.GetDMNInverseGCBoundaryForTesting(recovery_heads)};
    BOOST_REQUIRE(roster_moved.boundary);
    BOOST_CHECK(*roster_moved.boundary == *result.boundary);

    const int deep_fork{base + 20};
    auto deep_recovery{BuildForkedSnapshotIndexChain(
        active, deep_fork, active.Tip()->nHeight, 0x82)};
    const std::array<const CBlockIndex*, 1> deep_recovery_heads{
        deep_recovery.Tip()};
    result = manager.GetDMNInverseGCBoundaryForTesting(
        deep_recovery_heads);
    BOOST_CHECK(result.status == Status::BLOCKED);
    BOOST_REQUIRE(result.boundary);
    BOOST_CHECK_EQUAL(result.boundary->height, deep_fork);
    BOOST_CHECK_GT(active_floor - deep_fork, window);
}

BOOST_AUTO_TEST_CASE(auxiliary_retention_plan_allows_null_tip_flush)
{
    SelectParams(ChainType::MAIN);
    const int height{Params().GetConsensus().DIP0003Height};
    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_auxiliary_null_tip",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.m_evoDb->WriteCache(MakeSnapshotKey(height),
                                MakeSnapshot(height));

    const auto plan{
        manager.GetAuxiliaryHistoryRetentionPlanForTesting()};
    BOOST_CHECK(plan.requirements_valid);
    BOOST_CHECK(plan.branches.empty());
    BOOST_CHECK(!plan.AllowsDestructiveGC());
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    CDeterministicMNList persisted;
    BOOST_REQUIRE(manager.m_evoDb->Read(MakeSnapshotKey(height), persisted));
    BOOST_CHECK_EQUAL(persisted.GetHeight(), height);
}

BOOST_AUTO_TEST_CASE(auxiliary_retention_mutators_share_maintenance_barrier)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus{const_cast<Consensus::Params&>(Params().GetConsensus())};
    struct RestoreAnchor {
        Consensus::Params& consensus;
        int height{consensus.nPQChainLockAnchorHeight};
        uint256 hash{consensus.hashPQChainLockAnchorBlock};
        ~RestoreAnchor()
        {
            consensus.nPQChainLockAnchorHeight = height;
            consensus.hashPQChainLockAnchorBlock = hash;
        }
    } restore{consensus};
    const int anchor_height{consensus.DIP0003Height + 5};
    const uint256 anchor_hash{MakeSnapshotKey(anchor_height)};
    consensus.nPQChainLockAnchorHeight = anchor_height;
    consensus.hashPQChainLockAnchorBlock = anchor_hash;

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_auxiliary_retention_barrier",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    const auto expect_serialized = [&](auto operation) {
        std::promise<void> entered;
        std::promise<void> completed;
        auto entered_future{entered.get_future()};
        auto completed_future{completed.get_future()};
        std::thread worker;
        bool blocked{false};
        {
            LOCK(manager.m_evoDb->cs);
            worker = std::thread([&] {
                entered.set_value();
                operation();
                completed.set_value();
            });
            entered_future.wait();
            blocked = completed_future.wait_for(
                std::chrono::milliseconds{50}) ==
                std::future_status::timeout;
        }
        completed_future.wait();
        worker.join();
        BOOST_CHECK(blocked);
    };

    expect_serialized([&] {
        (void)manager.UpdateReplaySnapshotRetentionFloor(anchor_height);
    });
    expect_serialized([&] {
        (void)manager.UpdateFinalitySnapshotRetentionFloor(anchor_height);
    });
    expect_serialized([&] { manager.UpdatedBlockTip(nullptr); });
    expect_serialized([&] {
        const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
            authorization{
                CDeterministicMNManager::
                    AuxiliaryHistoryGCAuthorizationSource::
                        IMMUTABLE_CHAINLOCK_ANCHOR,
                {anchor_height, anchor_hash}};
        (void)manager.UpdateAuxiliaryHistoryGCAuthorization(
            authorization);
    });
}

BOOST_AUTO_TEST_CASE(finality_floor_skips_retained_values_before_decoding)
{
    SelectParams(ChainType::MAIN);
    const int cache_limit{CDeterministicMNManager::LIST_CACHE_SIZE};
    const int hot_cache_limit{CDeterministicMNManager::HOT_LIST_CACHE_SIZE};
    const int start_height{Params().GetConsensus().DIP0003Height};
    const int total_snapshots{cache_limit + hot_cache_limit + 8};
    const auto chain{BuildSnapshotIndexChain(start_height, total_snapshots)};
    const int oldest_retained_height{
        chain.Tip()->nHeight - cache_limit + 1};
    const int finality_floor{chain.Tip()->nHeight - 16};

    CDeterministicMNManager manager(DBParams{
        .path = "testdb_dmn_retained_value_skip",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    });
    manager.UpdatedBlockTip(chain.Tip());
    for (int height{oldest_retained_height};
         height <= chain.Tip()->nHeight; ++height) {
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            MakeSnapshotKey(height), MakeSnapshot(height),
            /*fSync=*/true));
    }

    // This retained active-chain key is deliberately outside the hot cache.
    // Maintenance owns only its lifetime; consumers validate its value when
    // they actually load the snapshot.
    const uint256 retained_hash{MakeSnapshotKey(oldest_retained_height)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        retained_hash,
        CDeterministicMNList{
            MakeSnapshotKey(oldest_retained_height + 1),
            oldest_retained_height, 0},
        /*fSync=*/true));

    const uint256 old_side_hash{
        MakeSnapshotKey(start_height + total_snapshots + 100)};
    const uint256 retained_side_hash{
        MakeSnapshotKey(start_height + total_snapshots + 101)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        old_side_hash,
        CDeterministicMNList{old_side_hash, finality_floor - 1, 0},
        /*fSync=*/true));
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        retained_side_hash,
        CDeterministicMNList{retained_side_hash, finality_floor, 0},
        /*fSync=*/true));

    BOOST_CHECK_EQUAL(
        manager.UpdateFinalitySnapshotRetentionFloor(finality_floor),
        finality_floor);
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_CHECK(manager.m_evoDb->ExistsCache(retained_hash));
    BOOST_CHECK(!manager.VerifyPersistedSnapshot(
        chain.At(oldest_retained_height)));

    CDeterministicMNList snapshot;
    BOOST_CHECK(!manager.m_evoDb->Read(old_side_hash, snapshot));
    BOOST_REQUIRE(manager.m_evoDb->Read(retained_side_hash, snapshot));
    BOOST_CHECK_EQUAL(snapshot.GetHeight(), finality_floor);

    BOOST_REQUIRE(manager.m_evoDb->AppendTrailingValueByteForTesting(
        retained_side_hash));
    manager.BeginFinalitySnapshotVerificationRetention();
    manager.EndFinalitySnapshotVerificationRetention();
    BOOST_CHECK(!manager.FlushCacheToDisk(/*bForceFlush=*/true));
    BOOST_REQUIRE(manager.m_evoDb->RewriteExactValueForTesting(
        retained_side_hash));
    manager.BeginFinalitySnapshotVerificationRetention();
    manager.EndFinalitySnapshotVerificationRetention();
    BOOST_REQUIRE(manager.FlushCacheToDisk(/*bForceFlush=*/true));

    // Side-branch values remain fail-closed under the same floor.
    const uint256 corrupt_side_hash{
        MakeSnapshotKey(start_height + total_snapshots + 102)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        corrupt_side_hash,
        CDeterministicMNList{
            MakeSnapshotKey(start_height + total_snapshots + 103),
            finality_floor, 0},
        /*fSync=*/true));
    manager.BeginFinalitySnapshotVerificationRetention();
    manager.EndFinalitySnapshotVerificationRetention();
    BOOST_CHECK(!manager.FlushCacheToDisk(/*bForceFlush=*/true));
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

BOOST_FIXTURE_TEST_CASE(
    nonempty_deep_rollback_reconstructs_pruned_parents_after_restart,
    ChainTestingSetup)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    auto& consensus = const_cast<Consensus::Params&>(Params().GetConsensus());
    struct RestoreProfile {
        Consensus::Params& consensus;
        bool regtest{fRegTest};
        int preparation_height{consensus.nPQPreparationHeight};
        int epoch_origin{consensus.nPQChainLockEpochOrigin};
        uint32_t cutoff{consensus.nPQRegistrationCutoffBlocks};
        uint32_t future{consensus.nPQFutureHorizonEpochs};
        int anchor_height{consensus.nPQLegacyAnchorHeight};
        uint256 anchor_hash{consensus.hashPQLegacyAnchorBlock};
        uint256 anchor_mn_state{consensus.hashPQLegacyMNState};
        uint256 anchor_pq_state{consensus.hashPQLegacyPQRegistryState};
        int chainlock_anchor_height{consensus.nPQChainLockAnchorHeight};
        uint256 chainlock_anchor_hash{consensus.hashPQChainLockAnchorBlock};
        ~RestoreProfile()
        {
            fRegTest = regtest;
            consensus.nPQPreparationHeight = preparation_height;
            consensus.nPQChainLockEpochOrigin = epoch_origin;
            consensus.nPQRegistrationCutoffBlocks = cutoff;
            consensus.nPQFutureHorizonEpochs = future;
            consensus.nPQLegacyAnchorHeight = anchor_height;
            consensus.hashPQLegacyAnchorBlock = anchor_hash;
            consensus.hashPQLegacyMNState = anchor_mn_state;
            consensus.hashPQLegacyPQRegistryState = anchor_pq_state;
            consensus.nPQChainLockAnchorHeight = chainlock_anchor_height;
            consensus.hashPQChainLockAnchorBlock = chainlock_anchor_hash;
        }
    } restore{consensus};
    fRegTest = false;
    consensus.nPQPreparationHeight = std::numeric_limits<int>::max();
    consensus.nPQChainLockEpochOrigin = std::numeric_limits<int>::max();
    consensus.nPQRegistrationCutoffBlocks = 0;
    consensus.nPQFutureHorizonEpochs = 0;
    consensus.nPQLegacyAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQLegacyAnchorBlock.SetNull();
    consensus.hashPQLegacyMNState.SetNull();
    consensus.hashPQLegacyPQRegistryState.SetNull();
    consensus.nPQChainLockAnchorHeight = std::numeric_limits<int>::max();
    consensus.hashPQChainLockAnchorBlock.SetNull();

    const int start_height{consensus.DIP0003Height};
    constexpr int gc_boundary_offset{300};
    const int rollback_depth{
        CDeterministicMNManager::LIST_CACHE_SIZE + gc_boundary_offset};
    std::vector<uint256> hashes(static_cast<size_t>(rollback_depth + 1));
    std::vector<CBlockIndex> indices(static_cast<size_t>(rollback_depth + 1));
    hashes[0] = MakeSnapshotKey(start_height);
    indices[0].nHeight = start_height;
    indices[0].phashBlock = &hashes[0];
    const CDeterministicMNList base_snapshot{
        MakeNontrivialAnchorSnapshot(hashes[0], start_height, false)};
    const uint256 base_state_hash{base_snapshot.GetPQLegacyStateHash(
        consensus.hashGenesisBlock)};
    const ScopedDiskDBPath disk_db;
    auto db_params = DBParams{
        .path = disk_db.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    CDeterministicMNList expected_gc_boundary_snapshot;
    uint256 expected_gc_boundary_state_hash;
    std::optional<evo::AuxiliaryHistoryGCComponent>
        expected_gc_component;

    {
        CDeterministicMNManager manager(db_params);
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            hashes[0], base_snapshot, /*fSync=*/true));
        CCoinsView base_view;
        CCoinsViewCache view(&base_view);
        const llmq::CFinalCommitmentTxPayload no_legacy_commitment;

        const uint256 empty_base_hash{
            MakeSnapshotKey(start_height + rollback_depth + 100)};
        CBlockIndex empty_base_index;
        empty_base_index.nHeight = start_height;
        empty_base_index.phashBlock = &empty_base_hash;
        BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
            empty_base_hash,
            CDeterministicMNList{empty_base_hash, start_height, 0},
            /*fSync=*/true));
        CBlock empty_block{MakeProviderMutationBlock({})};
        empty_block.hashPrevBlock = empty_base_hash;
        empty_block.nTime = 0xf00d;
        empty_block.nNonce = 0xbeef;
        const uint256 empty_child_hash{empty_block.GetHash()};
        CBlockIndex empty_child_index;
        empty_child_index.nHeight = start_height + 1;
        empty_child_index.pprev = &empty_base_index;
        empty_child_index.phashBlock = &empty_child_hash;
        BlockValidationState empty_state;
        CDeterministicMNListNEVMAddressDiff empty_nevm_diff;
        BOOST_REQUIRE(manager.ProcessBlock(
            empty_block, &empty_child_index, empty_state, view,
            no_legacy_commitment, empty_nevm_diff,
            /*fJustCheck=*/false, /*ibd=*/true));
        CDeterministicMNManager::InverseJournalEntryStatsForTesting
            empty_stats;
        BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
            empty_child_hash, empty_stats));
        BOOST_CHECK_EQUAL(empty_stats.added_mns, 0U);
        BOOST_CHECK_EQUAL(empty_stats.updated_mns, 0U);
        BOOST_CHECK_EQUAL(empty_stats.removed_mns, 0U);
        BOOST_CHECK_EQUAL(empty_stats.serialized_size, 245U);

        for (int offset{1}; offset <= rollback_depth; ++offset) {
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
            BOOST_REQUIRE_MESSAGE(
                manager.ProcessBlock(
                    block, &index, state, view, no_legacy_commitment, diff,
                    /*fJustCheck=*/false, /*ibd=*/true),
                state.ToString());
            if (offset == 1) {
                CDeterministicMNManager::InverseJournalEntryStatsForTesting
                    update_stats;
                BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
                    hashes[1], update_stats));
                BOOST_CHECK_EQUAL(update_stats.added_mns, 0U);
                BOOST_CHECK_EQUAL(update_stats.updated_mns, 1U);
                BOOST_CHECK_EQUAL(update_stats.removed_mns, 0U);
                BOOST_CHECK_EQUAL(update_stats.serialized_size, 251U);
                const auto stored_child{
                    manager.GetListForBlock(&indices[1])};
                BOOST_CHECK_EQUAL(
                    stored_child.TrackedChangeCountForTesting(), 0U);
                BOOST_CHECK(
                    stored_child.HasPQLegacyStateHashCacheForTesting(
                        consensus.hashGenesisBlock));
                BOOST_TEST_MESSAGE(
                    "DMN inverse payload sizes: empty=245 bytes, "
                    "one-state-update=251 bytes");
            }
            if (offset == gc_boundary_offset) {
                expected_gc_boundary_snapshot =
                    manager.GetListForBlock(
                        &indices[gc_boundary_offset]);
                expected_gc_boundary_state_hash =
                    expected_gc_boundary_snapshot.GetPQLegacyStateHash(
                        consensus.hashGenesisBlock);
            }
        }
        manager.UpdatedBlockTip(&indices.back());
        BOOST_REQUIRE(manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/true));
        BOOST_CHECK_EQUAL(manager.m_evoDb->CountPersistedEntries(),
                          CDeterministicMNManager::LIST_CACHE_SIZE);
        BOOST_CHECK(!manager.VerifyPersistedSnapshot(&indices.front()));
    }

    // Reopen under the coordinated anchor profile. The empty auxiliary-GC
    // schema may rebind before any intent, while the already-built DMN and
    // inverse stores remain unchanged.
    consensus.nPQLegacyAnchorHeight = start_height;
    consensus.hashPQLegacyAnchorBlock = hashes[0];
    consensus.hashPQLegacyMNState = base_state_hash;
    consensus.hashPQLegacyPQRegistryState = MakeSnapshotKey(0x5047c001);
    consensus.nPQChainLockAnchorHeight = start_height;
    consensus.hashPQChainLockAnchorBlock = hashes[0];
    db_params.wipe_data = false;
    {
        CDeterministicMNManager manager(db_params);
        manager.UpdatedBlockTip(&indices.back());
        BOOST_CHECK_EQUAL(
            manager.UpdateFinalitySnapshotRetentionFloor(start_height),
            start_height);
        using Source = CDeterministicMNManager::
            AuxiliaryHistoryGCAuthorizationSource;
        using Status =
            CDeterministicMNManager::DMNInverseGCBoundaryStatus;
        const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
            gc_authorization{
            Source::ENFORCED_DURABLE_CHAINLOCK,
            {start_height + gc_boundary_offset,
             hashes[gc_boundary_offset]}};
        BOOST_REQUIRE(manager.UpdateAuxiliaryHistoryGCAuthorization(
            gc_authorization));

        const auto check_boundary = [&]() {
            const auto result{
                manager.GetDMNInverseGCBoundaryForTesting()};
            BOOST_REQUIRE(result.status == Status::READY);
            BOOST_REQUIRE(result.boundary);
            BOOST_REQUIRE(result.component);
            BOOST_CHECK_EQUAL(result.boundary->height,
                              start_height + gc_boundary_offset);
            BOOST_CHECK_EQUAL(result.boundary->block_hash,
                              hashes[gc_boundary_offset]);
            BOOST_CHECK_EQUAL(result.component->monotonic_position,
                              static_cast<uint64_t>(
                                  start_height + gc_boundary_offset));
            const auto closure{evo::DecodeDMNInverseGCClosure(
                result.component->closure)};
            BOOST_REQUIRE(closure);
            BOOST_CHECK(closure->boundary == *result.boundary);
            BOOST_CHECK_EQUAL(closure->boundary_state_hash,
                              expected_gc_boundary_state_hash);
            BOOST_CHECK(!closure->inverse_history_commitment.IsNull());
            BOOST_CHECK(!closure->inverse_record_hash.IsNull());
            const auto encoded{evo::EncodeDMNInverseGCClosure(*closure)};
            BOOST_REQUIRE(encoded);
            BOOST_CHECK(*encoded == result.component->closure);
            return result;
        };
        const auto first_boundary{check_boundary()};
        BOOST_REQUIRE(first_boundary.component);
        expected_gc_component = first_boundary.component;
        BOOST_CHECK(evo::IsDMNInverseGCComponentBoundedByAuthorization(
            *first_boundary.component, gc_authorization));
        const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
            under_authorized{
                Source::ENFORCED_DURABLE_CHAINLOCK,
                {start_height + gc_boundary_offset - 1,
                 hashes[gc_boundary_offset - 1]}};
        BOOST_CHECK(!evo::IsDMNInverseGCComponentBoundedByAuthorization(
            *first_boundary.component, under_authorized));

        // SYSCOIN: Derivation reconstructs the boundary in memory; this stage
        // must not silently turn a closure proposal into a database mutation.
        CDeterministicMNList absent_boundary;
        BOOST_CHECK(!manager.m_evoDb->Read(
            hashes[gc_boundary_offset], absent_boundary));

        // A read-only derivation must not flush a pending tombstone while
        // distinguishing an absent optional B snapshot from corrupt state.
        manager.m_evoDb->EraseCache(hashes[gc_boundary_offset]);
        BOOST_CHECK_EQUAL(manager.m_evoDb->GetEraseCacheSize(), 1U);
        BOOST_CHECK(manager.GetDMNInverseGCBoundaryForTesting().status ==
                    Status::BLOCKED);
        BOOST_CHECK_EQUAL(manager.m_evoDb->GetEraseCacheSize(), 1U);
        BOOST_CHECK(!manager.m_evoDb->Read(
            hashes[gc_boundary_offset], absent_boundary));
        manager.m_evoDb->WriteCache(
            hashes[gc_boundary_offset], expected_gc_boundary_snapshot);
        BOOST_REQUIRE(manager.m_evoDb->FlushCacheToDisk(
            /*CHUNK_ITEMS=*/256, /*fSync=*/true));
        check_boundary();

        // Ordinary EvoDB reads accept a valid object prefix. The physical GC
        // path must reject the same snapshot and inverse with trailing bytes.
        BOOST_REQUIRE(manager.m_evoDb->AppendTrailingValueByteForTesting(
            hashes[gc_boundary_offset]));
        CDeterministicMNList prefix_snapshot;
        BOOST_REQUIRE(manager.m_evoDb->Read(
            hashes[gc_boundary_offset], prefix_snapshot));
        BOOST_CHECK(manager.GetDMNInverseGCBoundaryForTesting().status ==
                    Status::BLOCKED);
        BOOST_REQUIRE(
            manager.m_evoDb->RewriteExactValueForTesting(
                hashes[gc_boundary_offset]));
        check_boundary();

        BOOST_REQUIRE(
            manager.AppendInverseJournalTrailingByteForTesting(
                hashes[gc_boundary_offset]));
        CDeterministicMNManager::InverseJournalEntryStatsForTesting
            prefix_inverse_stats;
        BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset], prefix_inverse_stats));
        BOOST_CHECK(manager.GetDMNInverseGCBoundaryForTesting().status ==
                    Status::BLOCKED);
        BOOST_REQUIRE(
            manager.RewriteExactInverseJournalValueForTesting(
                hashes[gc_boundary_offset]));
        check_boundary();

        auto trailing{first_boundary.component->closure};
        trailing.push_back(0);
        BOOST_CHECK(!evo::DecodeDMNInverseGCClosure(trailing));
        auto wrong_guard{first_boundary.component->closure};
        wrong_guard.front() ^= 1;
        BOOST_CHECK(!evo::DecodeDMNInverseGCClosure(wrong_guard));

        // The selected floor is B+1, so I_(B+1) materializes the chosen
        // boundary while I_B remains its retained closure endpoint.
        BOOST_REQUIRE(manager.CorruptInverseJournalForTesting(
            hashes[gc_boundary_offset + 1]));
        BOOST_CHECK(manager.GetDMNInverseGCBoundaryForTesting().status ==
                    Status::BLOCKED);
        BOOST_REQUIRE(manager.CorruptInverseJournalForTesting(
            hashes[gc_boundary_offset + 1]));
        check_boundary();
        BOOST_REQUIRE(manager.CorruptInverseJournalForTesting(
            hashes[gc_boundary_offset]));
        BOOST_CHECK(manager.GetDMNInverseGCBoundaryForTesting().status ==
                    Status::BLOCKED);
        BOOST_REQUIRE(manager.CorruptInverseJournalForTesting(
            hashes[gc_boundary_offset]));
        check_boundary();

        // Read-only endpoint derivation reaches only I_B and I_(B-1). The
        // first durable frontier additionally authenticates the complete
        // inverse lineage back to H and must reject an intermediate record.
        BOOST_REQUIRE(
            manager.AppendInverseJournalTrailingByteForTesting(hashes[2]));
        BOOST_REQUIRE(manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(!manager.GetAuxiliaryHistoryGCStateForTesting().intent);
        BOOST_REQUIRE(
            manager.RewriteExactInverseJournalValueForTesting(hashes[2]));

        // Preparation has two independent durability barriers. Neither a
        // failed B snapshot fsync nor a failed inverse-WAL fsync may publish
        // an intent that a restart could mistake for deletion authority.
        manager.m_evoDb->FailNextSynchronousWriteThroughForTesting();
        BOOST_CHECK(!manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(!manager.GetAuxiliaryHistoryGCStateForTesting().intent);
        manager.FailNextInverseJournalSynchronousFlushForTesting();
        BOOST_CHECK(!manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(!manager.GetAuxiliaryHistoryGCStateForTesting().intent);

        BOOST_REQUIRE(manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        const auto prepared_state{
            manager.GetAuxiliaryHistoryGCStateForTesting()};
        BOOST_REQUIRE(prepared_state.intent);
        BOOST_CHECK(!prepared_state.watermark);
        BOOST_REQUIRE(prepared_state.intent->target.frontier.dmn);
        BOOST_CHECK(prepared_state.intent->target.frontier.dmn ==
                    first_boundary.component);
        BOOST_CHECK(!prepared_state.intent->target.frontier.pq_registry);
        BOOST_CHECK(!prepared_state.intent->target.pq_erase_manifest);
        CDeterministicMNManager::InverseJournalEntryStatsForTesting
            retained_preboundary_inverse;
        BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
            hashes[1], retained_preboundary_inverse));
        BOOST_REQUIRE(manager.VerifyPersistedSnapshot(
            &indices[gc_boundary_offset]));

        // A prolonged finality stall can move the ordinary random-access
        // window more than one full cache beyond B. Current-closure
        // authentication must remain O(1) and must not demand that new floor.
        constexpr int stalled_extension{
            CDeterministicMNManager::LIST_CACHE_SIZE + 8};
        std::vector<uint256> stalled_hashes(stalled_extension);
        std::vector<CBlockIndex> stalled_indexes(stalled_extension);
        for (int offset{0}; offset < stalled_extension; ++offset) {
            stalled_hashes[static_cast<size_t>(offset)] =
                MakeSnapshotKey(5'000'000 + offset);
            auto& index{stalled_indexes[static_cast<size_t>(offset)]};
            index.nHeight = indices.back().nHeight + offset + 1;
            index.pprev = offset == 0
                ? &indices.back()
                : &stalled_indexes[static_cast<size_t>(offset - 1)];
            index.phashBlock =
                &stalled_hashes[static_cast<size_t>(offset)];
        }
        manager.UpdatedBlockTip(&stalled_indexes.back());
        const auto stalled_boundary{
            manager.GetDMNInverseGCBoundaryForTesting(
                {}, prepared_state.intent->target.frontier.dmn)};
        BOOST_REQUIRE(stalled_boundary.status == Status::READY);
        BOOST_CHECK(stalled_boundary.component ==
                    prepared_state.intent->target.frontier.dmn);
        manager.UpdatedBlockTip(&indices.back());

        // The first physical chunk is independently synchronous even when
        // ordinary maintenance is not. A failed chunk keeps both the durable
        // intent and every not-yet-committed inverse record retryable.
        manager.FailNextInverseJournalSynchronousFlushForTesting();
        BOOST_CHECK(!manager.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(manager.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    prepared_state.intent);
        BOOST_REQUIRE(manager.GetInverseJournalEntryStatsForTesting(
            hashes[1], retained_preboundary_inverse));
    }

    const uint64_t inverse_disk_bytes{DirectorySizeBytes(
        SiblingDBPath(disk_db.path, "_inverse"))};
    BOOST_REQUIRE_GT(inverse_disk_bytes, 0U);
    BOOST_TEST_MESSAGE(strprintf(
        "DMN inverse LevelDB: %u records occupy %u bytes (%.1f bytes/record)",
        static_cast<unsigned>(rollback_depth + 1), inverse_disk_bytes,
        static_cast<double>(inverse_disk_bytes) /
            static_cast<double>(rollback_depth + 1)));

    db_params.wipe_data = false;
    {
        CDeterministicMNManager restarted(db_params);
        restarted.UpdatedBlockTip(&indices.back());
        BOOST_CHECK_EQUAL(
            restarted.UpdateFinalitySnapshotRetentionFloor(start_height),
            start_height);
        const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
            resumed_authorization{
                CDeterministicMNManager::
                    AuxiliaryHistoryGCAuthorizationSource::
                        ENFORCED_DURABLE_CHAINLOCK,
                {start_height + gc_boundary_offset,
                 hashes[gc_boundary_offset]}};
        BOOST_REQUIRE(restarted.UpdateAuxiliaryHistoryGCAuthorization(
            resumed_authorization));
        const auto resumed_state{
            restarted.GetAuxiliaryHistoryGCStateForTesting()};
        BOOST_REQUIRE(resumed_state.intent);

        // The bounded physical scan must reject strict-decoding failures in
        // every record, not only at the retained B endpoint. Choose the
        // lexicographically first non-B chain record so the first pass is
        // guaranteed to encounter it before reaching its erase budget.
        size_t malformed_scan_offset{1};
        for (size_t offset{2}; offset < hashes.size(); ++offset) {
            if (offset != static_cast<size_t>(gc_boundary_offset) &&
                (malformed_scan_offset ==
                     static_cast<size_t>(gc_boundary_offset) ||
                 hashes[offset] < hashes[malformed_scan_offset])) {
                malformed_scan_offset = offset;
            }
        }
        BOOST_REQUIRE_NE(malformed_scan_offset,
                         static_cast<size_t>(gc_boundary_offset));
        BOOST_REQUIRE(
            restarted.AppendInverseJournalTrailingByteForTesting(
                hashes[malformed_scan_offset]));
        BOOST_CHECK(!restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(restarted.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    resumed_state.intent);
        BOOST_REQUIRE(
            restarted.RewriteExactInverseJournalValueForTesting(
                hashes[malformed_scan_offset]));

        // First use has more than one erase chunk. Each same-tip pass removes
        // at most 256 child heights below B and leaves the durable intent
        // pending; reaching EOF after erases starts a fresh absence cycle.
        BOOST_REQUIRE(restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(restarted.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    resumed_state.intent);
        BOOST_REQUIRE(restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(restarted.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    resumed_state.intent);
        CDeterministicMNManager::InverseJournalEntryStatsForTesting
            erased_inverse;
        BOOST_CHECK(!restarted.GetInverseJournalEntryStatsForTesting(
            hashes[1], erased_inverse));
        BOOST_CHECK(!restarted.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset - 1], erased_inverse));
        BOOST_REQUIRE(restarted.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset], erased_inverse));

        // The final deletion-free cycle authenticates both physical halves of
        // the closure. Neither a prefix-decodable B snapshot nor I_B may
        // authorize completion.
        BOOST_REQUIRE(restarted.m_evoDb->AppendTrailingValueByteForTesting(
            hashes[gc_boundary_offset]));
        BOOST_CHECK(!restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_REQUIRE(
            restarted.m_evoDb->RewriteExactValueForTesting(
                hashes[gc_boundary_offset]));
        BOOST_REQUIRE(
            restarted.AppendInverseJournalTrailingByteForTesting(
                hashes[gc_boundary_offset]));
        BOOST_CHECK(!restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_REQUIRE(
            restarted.RewriteExactInverseJournalValueForTesting(
                hashes[gc_boundary_offset]));

        // A failure after all inverse chunks are durable must leave the exact
        // pending target for restart; it must not resurrect the erased prefix.
        restarted.FailNextAuxiliaryHistoryGCCompleteForTesting();
        BOOST_CHECK(!restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(restarted.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    resumed_state.intent);
        BOOST_CHECK(!restarted.GetInverseJournalEntryStatsForTesting(
            hashes[1], erased_inverse));
        BOOST_REQUIRE(restarted.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset], erased_inverse));
    }

    {
        CDeterministicMNManager restarted(db_params);
        restarted.UpdatedBlockTip(&indices.back());
        BOOST_CHECK_EQUAL(
            restarted.UpdateFinalitySnapshotRetentionFloor(start_height),
            start_height);
        const CDeterministicMNManager::AuxiliaryHistoryGCAuthorization
            resumed_authorization{
                CDeterministicMNManager::
                    AuxiliaryHistoryGCAuthorizationSource::
                        ENFORCED_DURABLE_CHAINLOCK,
                {start_height + gc_boundary_offset,
                 hashes[gc_boundary_offset]}};
        BOOST_REQUIRE(restarted.UpdateAuxiliaryHistoryGCAuthorization(
            resumed_authorization));
        BOOST_REQUIRE(
            restarted.GetAuxiliaryHistoryGCStateForTesting().intent);
        BOOST_REQUIRE(restarted.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        const auto completed_state{
            restarted.GetAuxiliaryHistoryGCStateForTesting()};
        BOOST_CHECK(!completed_state.intent);
        BOOST_REQUIRE(completed_state.watermark);
        BOOST_REQUIRE(completed_state.watermark->frontier.dmn);
        BOOST_CHECK(completed_state.watermark->frontier.dmn ==
                    expected_gc_component);

        // Recovery heads below B or on a branch with a different block at B
        // cannot widen the random-access window across the durable floor.
        const std::array<const CBlockIndex*, 1> below_boundary_recovery{
            &indices[gc_boundary_offset - 1]};
        BOOST_CHECK(!restarted.GetAuxiliaryHistoryRetentionPlanForTesting(
                                  below_boundary_recovery)
                         .requirements_valid);
        uint256 wrong_boundary_hash{MakeSnapshotKey(7'000'004)};
        uint256 wrong_child_hash{MakeSnapshotKey(7'000'005)};
        CBlockIndex wrong_boundary;
        wrong_boundary.nHeight = start_height + gc_boundary_offset;
        wrong_boundary.pprev = &indices[gc_boundary_offset - 1];
        wrong_boundary.phashBlock = &wrong_boundary_hash;
        CBlockIndex wrong_child;
        wrong_child.nHeight = start_height + gc_boundary_offset + 1;
        wrong_child.pprev = &wrong_boundary;
        wrong_child.phashBlock = &wrong_child_hash;
        const std::array<const CBlockIndex*, 1> wrong_branch_recovery{
            &wrong_child};
        BOOST_CHECK(!restarted.GetAuxiliaryHistoryRetentionPlanForTesting(
                                  wrong_branch_recovery)
                         .requirements_valid);
        const uint64_t exact_authentications_before_wrong_undo{
            restarted.GetDMNInverseGCExactAuthenticationCountForTesting()};
        CDeterministicMNListNEVMAddressDiff wrong_branch_nevm;
        BOOST_CHECK(!restarted.UndoBlock(
            &wrong_child, wrong_branch_nevm));
        BOOST_CHECK_EQUAL(
            restarted.GetDMNInverseGCExactAuthenticationCountForTesting(),
            exact_authentications_before_wrong_undo);

        BOOST_REQUIRE(restarted.VerifyPersistedSnapshot(&indices.back()));
        BOOST_REQUIRE(restarted.VerifyInverseJournalTipSeal(&indices.back()));
        const uint64_t exact_authentications_before_disconnects{
            restarted.GetDMNInverseGCExactAuthenticationCountForTesting()};
        for (int offset{rollback_depth};
             offset > gc_boundary_offset; --offset) {
            CDeterministicMNListNEVMAddressDiff inverse_nevm;
            BOOST_TEST_CONTEXT("undo offset=" << offset) {
                BOOST_REQUIRE(restarted.UndoBlock(
                    &indices[static_cast<size_t>(offset)], inverse_nevm));
            }
            BOOST_REQUIRE(restarted.EnsureRetainedSnapshotWindow(
                &indices[static_cast<size_t>(offset - 1)]));
            restarted.UpdatedBlockTip(
                &indices[static_cast<size_t>(offset - 1)]);
        }
        BOOST_REQUIRE(restarted.EnsureRetainedSnapshotWindow(
            &indices[gc_boundary_offset]));
        BOOST_REQUIRE(restarted.VerifyInverseJournalTipSeal(
            &indices[gc_boundary_offset]));
        BOOST_CHECK_EQUAL(
            restarted.GetDMNInverseGCExactAuthenticationCountForTesting(),
            exact_authentications_before_disconnects);
        const auto boundary_plan{
            restarted.GetAuxiliaryHistoryRetentionPlanForTesting()};
        BOOST_REQUIRE(boundary_plan.requirements_valid);
        BOOST_REQUIRE_EQUAL(boundary_plan.branches.size(), 1U);
        BOOST_CHECK_EQUAL(
            boundary_plan.branches.front().random_access_floor.height,
            start_height + gc_boundary_offset);
        BOOST_CHECK_EQUAL(
            boundary_plan.branches.front().random_access_floor.block_hash,
            hashes[gc_boundary_offset]);
        CDeterministicMNListNEVMAddressDiff boundary_nevm;
        BOOST_CHECK(!restarted.UndoBlock(
            &indices[gc_boundary_offset], boundary_nevm));
        BOOST_REQUIRE(restarted.FlushPendingSnapshotsToDisk(/*fSync=*/true));
        BOOST_REQUIRE(restarted.VerifyPersistedSnapshot(
            &indices[gc_boundary_offset]));
        BOOST_CHECK(restarted.GetListForBlock(
                        &indices[gc_boundary_offset])
                        .GetPQLegacyStateHash(consensus.hashGenesisBlock) ==
                    expected_gc_boundary_state_hash);
    }

    {
        CDeterministicMNManager reopened(db_params);
        reopened.UpdatedBlockTip(&indices[gc_boundary_offset]);
        BOOST_REQUIRE(reopened.VerifyInverseJournalTipSeal(
            &indices[gc_boundary_offset]));
        BOOST_REQUIRE(reopened.VerifyPersistedSnapshot(
            &indices[gc_boundary_offset]));
        BOOST_CHECK(reopened.GetListForBlock(
                        &indices[gc_boundary_offset])
                        .GetPQLegacyStateHash(consensus.hashGenesisBlock) ==
                    expected_gc_boundary_state_hash);
        CDeterministicMNListNEVMAddressDiff inverse_nevm;
        BOOST_CHECK(!reopened.UndoBlock(
            &indices[gc_boundary_offset], inverse_nevm));
        CDeterministicMNManager::InverseJournalEntryStatsForTesting
            boundary_inverse;
        BOOST_REQUIRE(reopened.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset], boundary_inverse));
        BOOST_CHECK(!reopened.GetInverseJournalEntryStatsForTesting(
            hashes[gc_boundary_offset - 1], boundary_inverse));

        // SYSCOIN: A shared intent carrying a malformed PQ advance is not a
        // usable effective floor and must fail closed before either store can
        // complete it. Publish it last because the durable journal correctly
        // makes this corruption sticky across restart.
        const auto completed_state{
            reopened.GetAuxiliaryHistoryGCStateForTesting()};
        BOOST_REQUIRE(completed_state.watermark);
        evo::AuxiliaryHistoryGCIntentTarget combined_target;
        combined_target.authorization = {
            CDeterministicMNManager::
                AuxiliaryHistoryGCAuthorizationSource::
                    ENFORCED_DURABLE_CHAINLOCK,
            {start_height + gc_boundary_offset + 1,
             hashes[gc_boundary_offset + 1]}};
        combined_target.frontier = completed_state.watermark->frontier;
        combined_target.frontier.pq_registry =
            evo::AuxiliaryHistoryGCComponent{1, 1, {0x51}};
        combined_target.pq_erase_manifest =
            evo::AuxiliaryHistoryGCManifest{1, {0x52}};
        BOOST_REQUIRE(reopened.UpdateAuxiliaryHistoryGCAuthorization(
            combined_target.authorization));
        BOOST_REQUIRE(reopened.BeginAuxiliaryHistoryGCIntentForTesting(
            combined_target));
        const auto combined_state{
            reopened.GetAuxiliaryHistoryGCStateForTesting()};
        BOOST_REQUIRE(combined_state.intent);
        BOOST_CHECK(!reopened.GetAuxiliaryHistoryRetentionPlanForTesting()
                         .requirements_valid);
        BOOST_CHECK(!reopened.FlushCacheToDisk(
            /*bForceFlush=*/true, /*fSync=*/false));
        BOOST_CHECK(reopened.GetAuxiliaryHistoryGCStateForTesting().intent ==
                    combined_state.intent);
    }
}

BOOST_AUTO_TEST_CASE(missing_inverse_coverage_fails_closed)
{
    SelectParams(ChainType::MAIN);
    LOCK(::cs_main);
    const int parent_height{Params().GetConsensus().DIP0003Height};
    auto chain{BuildSnapshotIndexChain(parent_height, 2)};
    auto db_params = DBParams{
        .path = "testdb_dmn_missing_inverse",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        chain.Tip()->GetBlockHash(),
        CDeterministicMNList{chain.Tip()->GetBlockHash(),
                             chain.Tip()->nHeight, 0},
        /*fSync=*/true));

    CDeterministicMNListNEVMAddressDiff inverse_nevm;
    BOOST_CHECK(!manager.VerifyInverseJournalTipSeal(chain.Tip()));
    BOOST_CHECK(!manager.UndoBlock(chain.Tip(), inverse_nevm));
    BOOST_CHECK(!manager.VerifyPersistedSnapshot(chain.At(parent_height)));
}

BOOST_FIXTURE_TEST_CASE(
    corrupt_inverse_parent_hash_is_rejected_before_undo,
    ChainTestingSetup)
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

    const int base_height{consensus.DIP0003Height};
    std::array<uint256, 2> hashes{MakeSnapshotKey(base_height), uint256{}};
    std::array<CBlockIndex, 2> indices;
    indices[0].nHeight = base_height;
    indices[0].phashBlock = &hashes[0];
    auto db_params = DBParams{
        .path = "testdb_dmn_corrupt_inverse",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);
    const auto base_snapshot{
        MakeNontrivialAnchorSnapshot(hashes[0], base_height, false)};
    BOOST_REQUIRE(manager.m_evoDb->WriteThrough(
        hashes[0], base_snapshot, /*fSync=*/true));

    CBlock block{MakeProviderMutationBlock({})};
    block.hashPrevBlock = hashes[0];
    block.nTime = 1;
    block.nNonce = 1;
    hashes[1] = block.GetHash();
    indices[1].nHeight = base_height + 1;
    indices[1].pprev = &indices[0];
    indices[1].phashBlock = &hashes[1];
    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    BlockValidationState state;
    CDeterministicMNListNEVMAddressDiff diff;
    BOOST_REQUIRE(manager.ProcessBlock(
        block, &indices[1], state, view,
        llmq::CFinalCommitmentTxPayload{}, diff,
        /*fJustCheck=*/false, /*ibd=*/true));
    BOOST_REQUIRE(manager.FlushPendingSnapshotsToDisk(/*fSync=*/true));
    BOOST_REQUIRE(manager.VerifyInverseJournalTipSeal(&indices[1]));
    BOOST_REQUIRE(manager.CorruptInverseJournalForTesting(hashes[1]));
    BOOST_CHECK(!manager.VerifyInverseJournalTipSeal(&indices[1]));

    CDeterministicMNListNEVMAddressDiff inverse_nevm;
    BOOST_CHECK(!manager.UndoBlock(&indices[1], inverse_nevm));
    BOOST_REQUIRE(manager.VerifyPersistedSnapshot(&indices[1]));

    // A tip seal intentionally does not rescan the complete LevelDB history.
    // If an older key is damaged after publication, sequential undo must stop
    // at the last verified link before reconstructing its missing parent (and
    // therefore before the later PQ-registry rollback stage is entered).
    constexpr int gap_depth{5};
    std::array<uint256, gap_depth + 1> gap_hashes;
    std::array<CBlockIndex, gap_depth + 1> gap_indices;
    gap_hashes[0] = MakeSnapshotKey(base_height + 100);
    gap_indices[0].nHeight = base_height;
    gap_indices[0].phashBlock = &gap_hashes[0];
    const ScopedDiskDBPath gap_disk;
    auto gap_db_params = DBParams{
        .path = gap_disk.path,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true,
    };
    {
        CDeterministicMNManager builder(gap_db_params);
        BOOST_REQUIRE(builder.m_evoDb->WriteThrough(
            gap_hashes[0],
            MakeNontrivialAnchorSnapshot(
                gap_hashes[0], base_height, false),
            /*fSync=*/true));
        CCoinsView gap_base_view;
        CCoinsViewCache gap_view(&gap_base_view);
        for (int offset{1}; offset <= gap_depth; ++offset) {
            CBlock gap_block{MakeProviderMutationBlock({})};
            gap_block.hashPrevBlock = gap_hashes[offset - 1];
            gap_block.nTime = static_cast<uint32_t>(50 + offset);
            gap_block.nNonce = static_cast<uint32_t>(100 + offset);
            gap_hashes[offset] = gap_block.GetHash();
            gap_indices[offset].nHeight = base_height + offset;
            gap_indices[offset].pprev = &gap_indices[offset - 1];
            gap_indices[offset].phashBlock = &gap_hashes[offset];
            BlockValidationState gap_state;
            CDeterministicMNListNEVMAddressDiff gap_diff;
            BOOST_REQUIRE_MESSAGE(builder.ProcessBlock(
                gap_block, &gap_indices[offset], gap_state, gap_view,
                llmq::CFinalCommitmentTxPayload{}, gap_diff,
                /*fJustCheck=*/false, /*ibd=*/true),
                gap_state.ToString());
        }
        BOOST_REQUIRE(builder.FlushPendingSnapshotsToDisk(/*fSync=*/true));
    }

    gap_db_params.wipe_data = false;
    {
        CDeterministicMNManager damaged(gap_db_params);
        BOOST_REQUIRE(damaged.EraseInverseJournalEntryForTesting(
            gap_hashes[2]));
        damaged.m_evoDb->EraseCache(gap_hashes[2]);
        BOOST_REQUIRE(damaged.m_evoDb->FlushCacheToDisk(
            /*CHUNK_ITEMS=*/256, /*fSync=*/true));
    }

    {
        CDeterministicMNManager restarted(gap_db_params);
        BOOST_REQUIRE(restarted.VerifyInverseJournalTipSeal(
            &gap_indices.back()));
        CDeterministicMNList gap_child_before;
        BOOST_REQUIRE(restarted.m_evoDb->Read(
            gap_hashes[3], gap_child_before));
        const uint256 gap_child_state_hash{
            gap_child_before.GetPQLegacyStateHash(
                consensus.hashGenesisBlock)};

        CDeterministicMNListNEVMAddressDiff gap_nevm;
        BOOST_REQUIRE(restarted.UndoBlock(&gap_indices[5], gap_nevm));
        gap_nevm = {};
        BOOST_REQUIRE(restarted.UndoBlock(&gap_indices[4], gap_nevm));
        BOOST_CHECK(!restarted.VerifyPersistedSnapshot(&gap_indices[2]));
        gap_nevm = {};
        BOOST_CHECK(!restarted.UndoBlock(&gap_indices[3], gap_nevm));
        BOOST_CHECK(gap_nevm.addedMNNEVM.empty());
        BOOST_CHECK(gap_nevm.updatedMNNEVM.empty());
        BOOST_CHECK(gap_nevm.removedMNNEVM.empty());
        BOOST_CHECK(!restarted.VerifyPersistedSnapshot(&gap_indices[2]));

        CDeterministicMNList gap_child_after;
        BOOST_REQUIRE(restarted.m_evoDb->Read(
            gap_hashes[3], gap_child_after));
        BOOST_CHECK(gap_child_after.GetPQLegacyStateHash(
                        consensus.hashGenesisBlock) ==
                    gap_child_state_hash);
    }
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
        int dip3_height{consensus.DIP0003Height};
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
            consensus.DIP0003Height = dip3_height;
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
    consensus.DIP0003Height = consensus.nPQPreparationHeight - 1;
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

BOOST_AUTO_TEST_CASE(legacy_operator_scheme_migration_preserves_operator_state)
{
    SelectParams(ChainType::REGTEST);
    const int parent_height{std::max(Params().GetConsensus().DIP0003Height, 1)};
    const uint256 parent_hash{MakeSnapshotKey(parent_height)};
    CBlockIndex parent_index;
    parent_index.nHeight = parent_height;
    parent_index.phashBlock = &parent_hash;

    auto db_params = DBParams{
        .path = "testdb_dmn_legacy_operator_scheme_migration",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true,
    };
    CDeterministicMNManager manager(db_params);

    // The first same-key v1-to-v2 migration on mainnet occurred in ProUpReg
    // dee303e3... at height 1,625,508 and must not reset operator state.
    const auto legacy_bytes{ParseHex(
        "0171e2a623a3f2709cb7d1802860be86ed5f5ef78c09c166"
        "f3f58369e1bbd55b50a47f3ca5464819b21131026d678afb")};
    const auto basic_bytes{ParseHex(
        "8171e2a623a3f2709cb7d1802860be86ed5f5ef78c09c166"
        "f3f58369e1bbd55b50a47f3ca5464819b21131026d678afb")};
    CLegacyBLSPublicKey legacy_key;
    CLegacyBLSPublicKey basic_key;
    BOOST_REQUIRE(legacy_key.SetBytes(legacy_bytes));
    BOOST_REQUIRE(basic_key.SetBytes(basic_bytes));

    auto member = std::make_shared<CDeterministicMN>(1);
    member->proTxHash = MakeSnapshotKey(30'001);
    member->collateralOutpoint = COutPoint{MakeSnapshotKey(30'002), 0};
    auto member_state = std::make_shared<CDeterministicMNState>();
    member_state->nVersion = CProRegTx::LEGACY_BLS_VERSION;
    member_state->nRegisteredHeight = parent_height - 1;
    member_state->nCollateralHeight = parent_height - 1;
    member_state->confirmedHash = MakeSnapshotKey(30'003);
    member_state->confirmedHashWithProRegTxHash = MakeSnapshotKey(30'004);
    member_state->keyIDOwner = MakeAnchorKeyID(0x21);
    member_state->keyIDVoting = MakeAnchorKeyID(0x31);
    member_state->pubKeyOperator = legacy_key;
    member_state->scriptPayout = CScript{} << OP_TRUE;
    member_state->scriptOperatorPayout = CScript{} << OP_DUP;
    member_state->vchNEVMAddress = {1, 2, 3, 4};
    member->pdmnState = member_state;

    CDeterministicMNList parent_list{parent_hash, parent_height, 1};
    parent_list.AddMN(member, /*fBumpTotalCount=*/false);
    manager.m_evoDb->WriteCache(parent_hash, parent_list);

    CCoinsView base_view;
    CCoinsViewCache view(&base_view);
    const llmq::CFinalCommitmentTxPayload no_legacy_commitment;
    const auto build_update = [&](const CLegacyBLSPublicKey& operator_key) {
        CMutableTransaction tx;
        tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
        tx.vin.emplace_back(COutPoint{MakeSnapshotKey(30'005), 0});
        tx.vout.emplace_back(1, CScript{} << OP_TRUE);

        CProUpRegTx payload;
        payload.nVersion = CProUpRegTx::BASIC_BLS_VERSION;
        payload.proTxHash = member->proTxHash;
        payload.pubKeyOperator = operator_key;
        payload.keyIDVoting = member_state->keyIDVoting;
        payload.scriptPayout = member_state->scriptPayout;
        payload.inputsHash = MakeSnapshotKey(30'006);
        payload.vchSig.assign(1, 1);
        SetTxPayload(tx, payload);

        BlockValidationState state;
        CDeterministicMNList next_list;
        CDeterministicMNList old_list;
        BOOST_REQUIRE(manager.BuildNewListFromBlock(
            MakeProviderMutationBlock({MakeTransactionRef(std::move(tx))}),
            &parent_index, state, view, next_list, old_list,
            no_legacy_commitment));
        return next_list;
    };

    const auto migrated_list{build_update(basic_key)};
    const auto migrated{migrated_list.GetMN(member->proTxHash)};
    BOOST_REQUIRE(migrated);
    BOOST_CHECK_EQUAL(migrated->pdmnState->nVersion,
                      CProRegTx::LEGACY_BLS_VERSION);
    BOOST_CHECK(migrated->pdmnState->pubKeyOperator == legacy_key);
    BOOST_CHECK(!migrated->pdmnState->IsBanned());
    BOOST_CHECK(migrated->pdmnState->scriptOperatorPayout ==
                member_state->scriptOperatorPayout);
    BOOST_CHECK(migrated->pdmnState->vchNEVMAddress ==
                member_state->vchNEVMAddress);
    BOOST_CHECK(!migrated_list.m_changed_nevm_address);
    BOOST_REQUIRE(migrated_list.GetUniquePropertyMN(legacy_key));
    BOOST_CHECK(!migrated_list.HasUniqueProperty(basic_key));
    auto removable_list{migrated_list};
    BOOST_CHECK_NO_THROW(removable_list.RemoveMN(member->proTxHash));
    BOOST_CHECK(!removable_list.HasMN(member->proTxHash));

    auto changed_bytes{basic_bytes};
    changed_bytes.front() ^= 0x20U;
    CLegacyBLSPublicKey changed_key;
    BOOST_REQUIRE(changed_key.SetBytes(changed_bytes));
    const auto changed_list{build_update(changed_key)};
    const auto changed{changed_list.GetMN(member->proTxHash)};
    BOOST_REQUIRE(changed);
    BOOST_CHECK_EQUAL(changed->pdmnState->nVersion,
                      CProRegTx::BASIC_BLS_VERSION);
    BOOST_CHECK(changed->pdmnState->pubKeyOperator == changed_key);
    BOOST_CHECK(changed->pdmnState->IsBanned());
    BOOST_CHECK(changed->pdmnState->scriptOperatorPayout.empty());
    BOOST_CHECK(changed->pdmnState->vchNEVMAddress.empty());
    BOOST_CHECK(changed_list.m_changed_nevm_address);
    BOOST_REQUIRE(changed_list.GetUniquePropertyMN(changed_key));
    BOOST_CHECK(!changed_list.HasUniqueProperty(legacy_key));
}

BOOST_AUTO_TEST_SUITE_END()
