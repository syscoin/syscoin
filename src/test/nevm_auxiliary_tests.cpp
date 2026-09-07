// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <nevm/sha3.h>
#include <node/blockconnection.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <streams.h>
#include <sync.h>
#include <test/util/coins.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {
CMutableTransaction MakeAuxiliaryTransaction(uint8_t hash_type, const std::vector<uint8_t>& data)
{
    CNEVMData payload;
    payload.nVersionHashType = hash_type;
    payload.vchVersionHash = hash_type == NEVM_DATA_LEGACY_VERSION_BYTE ?
        dev::sha3(data).asBytes() : dev::blake2s(dev::bytesConstRef(data.data(), data.size())).asBytes();
    std::vector<unsigned char> commitment;
    payload.SerializeData(commitment);

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_NEVM_DATA_SHA3;
    tx.vout.emplace_back(0, CScript() << OP_RETURN << commitment);
    tx.vout.back().vchNEVMData = data;
    return tx;
}

struct AuxiliaryRetrySetup : TestChain100Setup {
    CBlockIndex* index{nullptr};
    COutPoint input;
    COutPoint output;

    AuxiliaryRetrySetup()
    {
        const CTransaction& funding = *m_coinbase_txns.front();
        CMutableTransaction tx = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'r', 'e', 't', 'r', 'y'});
        input = COutPoint{funding.GetHash(), 0};
        tx.vin.emplace_back(input);
        tx.vout.emplace_back(funding.vout.front().nValue - 1000, CScript() << OP_TRUE);
        FillableSigningProvider provider;
        provider.AddKey(coinbaseKey);
        SignatureData signature;
        BOOST_REQUIRE(SignSignature(provider, funding, tx, 0, SIGHASH_ALL, signature));
        output = COutPoint{tx.GetHash(), 1};

        const auto block = std::make_shared<const CBlock>(
            CreateBlock({tx}, CScript() << OP_TRUE, m_node.chainman->ActiveChainstate()));
        LOCK(cs_main);
        BlockValidationState state;
        bool new_block{false};
        BOOST_REQUIRE(m_node.chainman->AcceptBlock(block, state, &index, /*fRequested=*/true,
                                                  /*dbp=*/nullptr, &new_block, /*min_pow_checked=*/true));
        BOOST_REQUIRE(new_block);
        BOOST_REQUIRE(index);
        BOOST_REQUIRE(m_node.chainman->ActiveTip() == index->pprev);
    }

    std::shared_ptr<const CBlock> ReadCandidate(bool load_auxiliary_data = true)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    {
        auto block = std::make_shared<CBlock>();
        BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(*block, *index, load_auxiliary_data));
        BOOST_REQUIRE_EQUAL(block->vtx.size(), 2U);
        BOOST_REQUIRE_EQUAL(HasNEVMAuxiliaryData(*block), load_auxiliary_data);
        return block;
    }

    void CheckRetry(bool require_data)
    {
        LOCK(cs_main);
        auto& chainstate = m_node.chainman->ActiveChainstate();
        auto& coins_tip = chainstate.CoinsTip();
        const uint256 tip_hash = coins_tip.GetBestBlock();
        SetMockTime(index->GetMedianTimePast() + (require_data ? 0 : NEVM_DATA_ENFORCE_TIME_HAVE_DATA + 1));
        auto block = ReadCandidate();
        const auto original = block;

        // The first failure is injected, not caused by invalid transaction or
        // blob bytes. Establish the ordinary attached representation as a control.
        BlockValidationState control_state;
        node::BlockConnectionState control{coins_tip};
        BOOST_REQUIRE(chainstate.ConnectBlock(*block, control_state, index, *control.view, /*fJustCheck=*/true,
                                              control.mint_txs, control.nevm_tx_roots, control.poda, control.txid_pairs));
        BOOST_REQUIRE_EQUAL(control.poda.size(), 1U);

        CCoinsViewCache parent{&coins_tip};
        node::BlockConnectionState connection{parent};
        BlockValidationState state;
        const uint256 marker{uint256S("01")};
        const std::vector<uint8_t> marker_key(32, 0x42);
        COutPoint staged_coin;
        unsigned int attempts{0};
        const auto result = node::ConnectBlockWithAuxiliaryRetry(
            m_node.chainman->m_blockman, *index, /*loaded_from_disk=*/true, block, state, parent, connection,
            [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
                ++attempts;
                BOOST_REQUIRE(state.IsValid());
                BOOST_CHECK(state.GetRejectReason().empty());
                BOOST_CHECK(state.GetDebugMessage().empty());
                if (attempts == 1) {
                    BOOST_REQUIRE(HasNEVMAuxiliaryData(*block));
                    staged_coin = AddTestCoin(*connection.view);
                    connection.view->SetBestBlock(marker);
                    connection.mint_txs.insert(marker);
                    connection.nevm_tx_roots.emplace(marker, NEVMTxRoot{});
                    connection.poda.emplace(marker_key, MapPoDAPayloadMeta{marker, 0, 0});
                    connection.txid_pairs.emplace_back(marker, 0);
                    return state.Invalid(BlockValidationResult::BLOCK_AUX_DATA_INVALID,
                                         "injected-auxiliary-result", "first-attempt state");
                }
                BOOST_REQUIRE_EQUAL(attempts, 2U);
                BOOST_REQUIRE(!HasNEVMAuxiliaryData(*block));
                BOOST_REQUIRE(block->GetHash() == original->GetHash());
                BOOST_REQUIRE(block->vtx[1]->GetWitnessHash() == original->vtx[1]->GetWitnessHash());
                BOOST_REQUIRE_EQUAL(connection.view->GetCacheSize(), 0U);
                BOOST_REQUIRE(connection.view->GetBestBlock() == tip_hash);
                BOOST_REQUIRE(!connection.view->HaveCoin(staged_coin));
                BOOST_REQUIRE(connection.mint_txs.empty());
                BOOST_REQUIRE(connection.nevm_tx_roots.empty());
                BOOST_REQUIRE(connection.poda.empty());
                BOOST_REQUIRE(connection.txid_pairs.empty());
                return chainstate.ConnectBlock(*block, state, index, *connection.view, /*fJustCheck=*/false,
                                               connection.mint_txs, connection.nevm_tx_roots,
                                               connection.poda, connection.txid_pairs);
            });

        BOOST_CHECK_EQUAL(attempts, 2U);
        BOOST_CHECK(block != original);
        BOOST_CHECK(HasNEVMAuxiliaryData(*original));
        BOOST_CHECK(!HasNEVMAuxiliaryData(*block));
        BOOST_CHECK(!parent.HaveCoin(staged_coin));
        BOOST_CHECK(parent.HaveCoin(input));
        BOOST_CHECK(!parent.HaveCoin(output));
        BOOST_CHECK(parent.GetBestBlock() == tip_hash);
        BOOST_CHECK_EQUAL(connection.mint_txs.count(marker), 0U);
        BOOST_CHECK_EQUAL(connection.nevm_tx_roots.count(marker), 0U);
        BOOST_CHECK_EQUAL(connection.poda.count(marker_key), 0U);
        BOOST_CHECK(std::none_of(connection.txid_pairs.begin(), connection.txid_pairs.end(),
                                 [&](const auto& entry) { return entry.first == marker; }));

        if (require_data) {
            BOOST_CHECK(result == node::BlockConnectionResult::FAILED);
            BOOST_CHECK(state.IsInvalid());
            BOOST_CHECK_EQUAL(state.GetResult(), BlockValidationResult::BLOCK_AUX_DATA_INVALID);
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "poda-aux-data-invalid");
            BOOST_CHECK(!IsBlockRejectionCacheable(state.GetResult()));
            BOOST_CHECK(connection.poda.empty());
            BOOST_CHECK(connection.view->HaveCoin(input));
            BOOST_CHECK(!connection.view->HaveCoin(output));
        } else {
            BOOST_CHECK(result == node::BlockConnectionResult::SUCCESS);
            BOOST_CHECK(state.IsValid());
            BOOST_CHECK_EQUAL(connection.poda.size(), 1U);
            BOOST_CHECK(!connection.view->HaveCoin(input));
            BOOST_CHECK(connection.view->HaveCoin(output));
            BOOST_REQUIRE(connection.view->Flush());
            BOOST_CHECK(!parent.HaveCoin(staged_coin));
            BOOST_CHECK(!parent.HaveCoin(input));
            BOOST_CHECK(parent.HaveCoin(output));
            BOOST_CHECK(parent.GetBestBlock() == index->GetBlockHash());
        }
        BOOST_CHECK(coins_tip.GetBestBlock() == tip_hash);
        BOOST_CHECK(coins_tip.HaveCoin(input));
        BOOST_CHECK(!coins_tip.HaveCoin(output));
        BOOST_CHECK(m_node.chainman->ActiveTip() == index->pprev);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(nevm_auxiliary_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(commitments_and_auxiliary_limits_are_independent)
{
    const std::vector<uint8_t> data{'d', 'a', 't', 'a'};
    for (const uint8_t type : {NEVM_DATA_LEGACY_VERSION_BYTE, NEVM_DATA_BLAKE2S_VERSION_BYTE}) {
        const CMutableTransaction original = MakeAuxiliaryTransaction(type, data);
        const CTransaction valid{original};
        PoDAMAPMemory metadata;
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, valid, 100, 100, metadata),
                          ProcessNEVMDataResult::VALID);
        BOOST_REQUIRE_EQUAL(metadata.size(), 1U);

        CMutableTransaction varied{original};
        varied.vout.front().vchNEVMData.resize(MAX_NEVM_DATA_BLOB + 1);
        const CTransaction bounded{varied};
        const CNEVMData parsed{bounded};
        BOOST_CHECK(!parsed.IsNull());
        BOOST_CHECK(parsed.vchVersionHash == CNEVMData(valid).vchVersionHash);
        BOOST_CHECK(bounded.GetHash() == valid.GetHash());
        BOOST_CHECK(bounded.GetWitnessHash() == valid.GetWitnessHash());
        metadata.clear();
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, bounded, 100, 100, metadata),
                          ProcessNEVMDataResult::AUX_DATA_INVALID);
        BOOST_CHECK(metadata.empty());

        CBlock block;
        block.vtx = {MakeTransactionRef(bounded)};
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, block, 100, 100, metadata),
                          ProcessNEVMDataResult::AUX_DATA_INVALID);
        BOOST_CHECK(metadata.empty());

        varied.vout.front().vchNEVMData.clear();
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, CTransaction{varied}, 100, 100, metadata),
                          ProcessNEVMDataResult::AUX_DATA_INVALID);
        BOOST_CHECK(metadata.empty());
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, valid, 100, 100, metadata),
                          ProcessNEVMDataResult::VALID);
    }
}

BOOST_AUTO_TEST_CASE(auxiliary_output_placement_is_checked)
{
    CMutableTransaction tx = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'o', 'k'});
    tx.vout.emplace_back(0, CScript() << OP_RETURN);
    PoDAMAPMemory metadata;
    BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, CTransaction{tx}, 100, 100, metadata),
                      ProcessNEVMDataResult::VALID);
    metadata.clear();
    tx.vout.back().vchNEVMData = {'x'};
    BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, CTransaction{tx}, 100, 100, metadata),
                      ProcessNEVMDataResult::AUX_DATA_INVALID);
    BOOST_CHECK(metadata.empty());
}

BOOST_AUTO_TEST_CASE(committed_format_and_embedded_payload_checks_remain)
{
    CMutableTransaction tx = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'o', 'k'});
    tx.vout.front().scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>{1};
    PoDAMAPMemory metadata;
    BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, CTransaction{tx}, 100, 100, metadata),
                      ProcessNEVMDataResult::CONSENSUS_INVALID);
    BOOST_CHECK(metadata.empty());

    CNEVMData payload{CTransaction{MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'o', 'k'})}};
    std::vector<unsigned char> embedded;
    payload.SerializeData(embedded);
    CDataStream stream(embedded, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_PODA);
    stream << std::vector<uint8_t>(MAX_NEVM_DATA_BLOB + 1);
    const auto bytes = MakeUCharSpan(stream);
    const std::vector<unsigned char> serialized{bytes.begin(), bytes.end()};
    BOOST_CHECK_LT(payload.UnserializeFromData(serialized, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_PODA), 0);
    BOOST_CHECK(payload.IsNull());
}

BOOST_AUTO_TEST_CASE(rejection_cache_uses_only_stable_results)
{
    const CTransaction ordinary{CMutableTransaction{}};
    BOOST_CHECK(!IsTxRejectionCacheable(TxValidationResult::TX_RESULT_UNSET, ordinary));
    BOOST_CHECK(!IsTxRejectionCacheable(TxValidationResult::TX_AUX_DATA_INVALID, ordinary));
    BOOST_CHECK(!IsTxRejectionCacheable(TxValidationResult::TX_WITNESS_STRIPPED, ordinary));
    BOOST_CHECK(IsTxRejectionCacheable(TxValidationResult::TX_CONSENSUS, ordinary));
    BOOST_CHECK(IsTxRejectionCacheable(TxValidationResult::TX_NOT_STANDARD, ordinary));
    BOOST_CHECK(IsTxRejectionCacheable(TxValidationResult::TX_INPUTS_NOT_STANDARD, ordinary));
    BOOST_CHECK(IsTxRejectionCacheable(TxValidationResult::TX_WITNESS_MUTATED, ordinary));
    BOOST_CHECK(IsBlockRejectionCacheable(BlockValidationResult::BLOCK_CONSENSUS));
    BOOST_CHECK(!IsBlockRejectionCacheable(BlockValidationResult::BLOCK_RESULT_UNSET));
    BOOST_CHECK(!IsBlockRejectionCacheable(BlockValidationResult::BLOCK_MUTATED));
    BOOST_CHECK(!IsBlockRejectionCacheable(BlockValidationResult::BLOCK_AUX_DATA_INVALID));
}

BOOST_AUTO_TEST_CASE(optional_auxiliary_data_does_not_enable_identity_rejection_caching)
{
    CMutableTransaction tx = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'o', 'k'});
    const int64_t now = 100 + NEVM_DATA_ENFORCE_TIME_HAVE_DATA + 1;
    for (const bool include_data : {true, false}) {
        if (!include_data) tx.vout.front().vchNEVMData.clear();
        const CTransaction optional{tx};
        PoDAMAPMemory metadata;
        BOOST_CHECK_EQUAL(ProcessNEVMData(m_node.chainman->m_blockman, optional, 100, now, metadata),
                          ProcessNEVMDataResult::VALID);
        BOOST_CHECK_EQUAL(HasNEVMAuxiliaryData(optional), include_data);
        CBlock block;
        block.vtx = {MakeTransactionRef(optional)};
        BOOST_CHECK_EQUAL(HasNEVMAuxiliaryData(block), include_data);
        for (const auto result : {TxValidationResult::TX_CONSENSUS, TxValidationResult::TX_NOT_STANDARD,
                                  TxValidationResult::TX_MEMPOOL_POLICY, TxValidationResult::TX_CONFLICT}) {
            BOOST_CHECK(!IsTxRejectionCacheable(result, optional));
        }
    }
}

BOOST_AUTO_TEST_CASE(size_failure_classification_accounts_for_auxiliary_data)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{uint256S("01"), 0});
    tx.vout.emplace_back(0, CScript{});
    tx.vout.front().scriptPubKey.resize(MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR);
    TxValidationState ordinary;
    BOOST_CHECK(!CheckTransaction(CTransaction{tx}, ordinary));
    BOOST_CHECK_EQUAL(ordinary.GetResult(), TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(ordinary.GetRejectReason(), "bad-txns-oversize");

    tx.nVersion = SYSCOIN_TX_VERSION_NEVM_DATA_SHA3;
    tx.vout.front().vchNEVMData = {'x'};
    TxValidationState auxiliary;
    BOOST_CHECK(!CheckTransaction(CTransaction{tx}, auxiliary));
    BOOST_CHECK_EQUAL(auxiliary.GetResult(), TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(auxiliary.GetRejectReason(), "bad-txns-oversize");

    tx.vout.front().scriptPubKey.front() = OP_RETURN;
    TxValidationState unspendable;
    BOOST_CHECK(!CheckTransaction(CTransaction{tx}, unspendable));
    BOOST_CHECK_EQUAL(unspendable.GetResult(), TxValidationResult::TX_CONSENSUS);
    BOOST_CHECK_EQUAL(unspendable.GetRejectReason(), "bad-txns-oversize");
}

BOOST_AUTO_TEST_CASE(committed_size_omits_only_auxiliary_contributions)
{
    for (const size_t data_size : {0U, 1U, 99U, 100U, 101U, 200U}) {
        CMutableTransaction tx = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE,
                                                        std::vector<uint8_t>(data_size, 'x'));
        tx.vin.emplace_back(COutPoint{uint256S("01"), 0});
        tx.vout.emplace_back(0, CScript() << OP_TRUE);
        tx.vout.back().vchNEVMData.assign(200, 'y');
        for (const bool with_witness : {false, true}) {
            if (with_witness) tx.vin.front().scriptWitness.stack = {{1, 2, 3}};
            CMutableTransaction cleared{tx};
            for (auto& output : cleared.vout) output.vchNEVMData.clear();
            const CTransaction attached{tx};
            const CTransaction committed{cleared};
            CBlock attached_block;
            attached_block.SetNEVMVersion();
            attached_block.vtx = {MakeTransactionRef(attached)};
            CBlock committed_block;
            committed_block.SetNEVMVersion();
            committed_block.vtx = {MakeTransactionRef(committed)};

            for (const int version : {PROTOCOL_VERSION, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS}) {
                const auto committed_size = ::GetSerializeSize(attached, version, SER_SIZE | SER_NO_PODA);
                BOOST_CHECK_EQUAL(committed_size, ::GetSerializeSize(committed, version));
                BOOST_CHECK_EQUAL(::GetSerializeSize(attached, version) - committed_size,
                                  static_cast<size_t>(data_size * NEVM_DATA_SCALE_FACTOR));
                BOOST_CHECK_EQUAL(::GetSerializeSize(attached_block, version, SER_SIZE | SER_NO_PODA),
                                  ::GetSerializeSize(committed_block, version));
                attached_block.vchNEVMBlockData.assign(200, 'z');
                BOOST_CHECK_EQUAL(::GetSerializeSize(attached_block, version, SER_SIZE | SER_NO_PODA),
                                  ::GetSerializeSize(committed_block, version));

                CMutableTransaction ordinary{tx};
                ordinary.nVersion = CTransaction::CURRENT_VERSION;
                BOOST_CHECK_EQUAL(::GetSerializeSize(ordinary, version, SER_SIZE | SER_NO_PODA),
                                  ::GetSerializeSize(ordinary, version));
            }
            const auto committed_weight =
                ::GetSerializeSize(attached_block, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS, SER_SIZE | SER_NO_PODA) * (WITNESS_SCALE_FACTOR - 1) +
                ::GetSerializeSize(attached_block, PROTOCOL_VERSION, SER_SIZE | SER_NO_PODA);
            BOOST_CHECK_EQUAL(committed_weight, GetBlockWeight(committed_block));
        }
    }
}

BOOST_AUTO_TEST_CASE(committed_disk_reads_preserve_ordinary_blocks)
{
    LOCK(cs_main);
    const CBlockIndex* index = m_node.chainman->ActiveChain().Tip();
    BOOST_REQUIRE(index);
    CBlock with_auxiliary;
    CBlock committed;
    BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(with_auxiliary, *index));
    BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlockFromDisk(committed, *index, /*load_auxiliary_data=*/false));
    BOOST_CHECK(with_auxiliary.GetHash() == committed.GetHash());
    BOOST_REQUIRE_EQUAL(with_auxiliary.vtx.size(), committed.vtx.size());
    for (size_t i = 0; i < committed.vtx.size(); ++i) {
        BOOST_CHECK(with_auxiliary.vtx[i]->GetHash() == committed.vtx[i]->GetHash());
        BOOST_CHECK(with_auxiliary.vtx[i]->GetWitnessHash() == committed.vtx[i]->GetWitnessHash());
    }
    BlockValidationState state;
    BOOST_CHECK(CheckBlock(committed, state, Params().GetConsensus()));
}

BOOST_FIXTURE_TEST_CASE(disk_auxiliary_retry_reconnects_with_fresh_state, AuxiliaryRetrySetup)
{
    CheckRetry(/*require_data=*/false);
}

BOOST_FIXTURE_TEST_CASE(disk_auxiliary_retry_preserves_required_data_checks, AuxiliaryRetrySetup)
{
    CheckRetry(/*require_data=*/true);
}

BOOST_FIXTURE_TEST_CASE(disk_auxiliary_retry_is_limited_to_eligible_failures, AuxiliaryRetrySetup)
{
    LOCK(cs_main);
    struct Case {
        bool loaded_from_disk;
        bool with_auxiliary;
        bool success;
        BlockValidationResult failure;
    };
    for (const auto& test : {
             Case{true, true, true, BlockValidationResult::BLOCK_RESULT_UNSET},
             Case{false, true, false, BlockValidationResult::BLOCK_AUX_DATA_INVALID},
             Case{true, false, false, BlockValidationResult::BLOCK_AUX_DATA_INVALID},
             Case{true, true, false, BlockValidationResult::BLOCK_CONSENSUS},
             Case{true, true, false, BlockValidationResult::BLOCK_MUTATED}}) {
        auto block = ReadCandidate(test.with_auxiliary);
        const auto original = block;
        CCoinsViewCache parent{&m_node.chainman->ActiveChainstate().CoinsTip()};
        node::BlockConnectionState connection{parent};
        BlockValidationState state;
        unsigned int attempts{0};
        const uint256 marker{uint256S("01")};
        const auto result = node::ConnectBlockWithAuxiliaryRetry(
            m_node.chainman->m_blockman, *index, test.loaded_from_disk, block, state, parent, connection,
            [&] {
                ++attempts;
                connection.mint_txs.insert(marker);
                return test.success || state.Invalid(test.failure, "injected-result");
            });
        BOOST_CHECK_EQUAL(attempts, 1U);
        BOOST_CHECK(block == original);
        BOOST_CHECK_EQUAL(connection.mint_txs.count(marker), 1U);
        BOOST_CHECK(result == (test.success ? node::BlockConnectionResult::SUCCESS : node::BlockConnectionResult::FAILED));
        BOOST_CHECK_EQUAL(state.GetResult(), test.failure);
    }
}

BOOST_FIXTURE_TEST_CASE(disk_auxiliary_retry_preserves_reread_errors, AuxiliaryRetrySetup)
{
    LOCK(cs_main);
    auto block = ReadCandidate();
    const auto original = block;
    CCoinsViewCache parent{&m_node.chainman->ActiveChainstate().CoinsTip()};
    node::BlockConnectionState connection{parent};
    BlockValidationState state;
    unsigned int attempts{0};
    const uint256 marker{uint256S("01")};
    CBlockIndex mismatched_index;
    mismatched_index.nStatus = BLOCK_HAVE_DATA;
    mismatched_index.nFile = index->nFile;
    mismatched_index.nDataPos = index->nDataPos;
    // Exercise the real indexed-read failure without changing stored block bytes.
    mismatched_index.phashBlock = &marker;
    const auto result = node::ConnectBlockWithAuxiliaryRetry(
        m_node.chainman->m_blockman, mismatched_index, /*loaded_from_disk=*/true, block, state, parent, connection,
        [&] {
            ++attempts;
            connection.mint_txs.insert(marker);
            connection.view->SetBestBlock(marker);
            return state.Invalid(BlockValidationResult::BLOCK_AUX_DATA_INVALID, "injected-result");
        });
    BOOST_CHECK(result == node::BlockConnectionResult::DISK_READ_FAILED);
    BOOST_CHECK_EQUAL(attempts, 1U);
    BOOST_CHECK(block == original);
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK_EQUAL(state.GetResult(), BlockValidationResult::BLOCK_AUX_DATA_INVALID);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "injected-result");
    BOOST_CHECK_EQUAL(connection.mint_txs.count(marker), 1U);
    BOOST_CHECK(connection.view->GetBestBlock() == marker);
    BOOST_CHECK(parent.GetBestBlock() == index->pprev->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(admission_checks_auxiliary_data_before_orphan_eligibility)
{
    CMutableTransaction original = MakeAuxiliaryTransaction(NEVM_DATA_LEGACY_VERSION_BYTE, {'o', 'k'});
    original.vin.emplace_back(COutPoint{uint256S("01"), 0});
    CMutableTransaction varied{original};
    varied.vout.front().vchNEVMData.resize(MAX_NEVM_DATA_BLOB + 1);
    LOCK(cs_main);
    const auto auxiliary = m_node.chainman->ProcessTransaction(MakeTransactionRef(varied), /*test_accept=*/true);
    BOOST_CHECK(auxiliary.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(auxiliary.m_state.GetResult(), TxValidationResult::TX_AUX_DATA_INVALID);
    BOOST_CHECK(!IsTxRejectionCacheable(auxiliary.m_state.GetResult(), CTransaction{varied}));

    // Valid auxiliary data must still reach the ordinary missing-input checks.
    const auto missing = m_node.chainman->ProcessTransaction(MakeTransactionRef(original), /*test_accept=*/true);
    BOOST_CHECK(missing.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(missing.m_state.GetResult(), TxValidationResult::TX_MISSING_INPUTS);
    BOOST_CHECK(!IsTxRejectionCacheable(missing.m_state.GetResult(), CTransaction{original}));
}

BOOST_AUTO_TEST_SUITE_END()
