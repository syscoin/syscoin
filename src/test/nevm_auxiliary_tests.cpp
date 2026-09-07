// Copyright (c) 2026 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <nevm/sha3.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <sync.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cstdint>
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
    BOOST_CHECK_EQUAL(auxiliary.GetResult(), TxValidationResult::TX_AUX_DATA_INVALID);
    BOOST_CHECK_EQUAL(auxiliary.GetRejectReason(), "bad-txns-oversize");
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
