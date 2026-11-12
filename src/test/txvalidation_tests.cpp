// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h> // SYSCOIN: Sign ZDAG conflict fixtures.
#include <policy/packages.h> // SYSCOIN: Exercise deferred ZDAG package admission.
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h> // SYSCOIN: Authenticate ZDAG conflict fixtures.
#include <test/util/setup_common.h>
#include <test/util/txmempool.h> // SYSCOIN: Construct authenticated ZDAG mempool fixtures.
#include <validation.h>
#include <validationinterface.h> // SYSCOIN: Drain callbacks before checking retained payloads.

#include <boost/test/unit_test.hpp>


// SYSCOIN BEGIN: Inspect bounded conflict evidence without changing the production API.
struct ZdagMempoolTestAccess {
    static const auto& Conflicts(const CTxMemPool& pool) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
    {
        return pool.mapAssetAllocationConflicts;
    }

    static void SetConflictCapacity(CTxMemPool& pool, size_t capacity) EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
    {
        pool.m_max_zdag_conflicts = capacity;
    }
};

int CheckActorsInTransactionGraph(const CTxMemPool& mempool, const uint256& lookForTxHash);
// SYSCOIN END: Inspect bounded conflict evidence without changing the production API.

BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction coinbaseTx;

    coinbaseTx.nVersion = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccessful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

// SYSCOIN BEGIN: Cover authenticated ZDAG admission, retention, limits, and warning precedence.
struct ZdagMempoolSetup : TestChain100Setup {
    explicit ZdagMempoolSetup(bool tiny_mempool = false)
        : TestChain100Setup(ChainType::REGTEST,
              tiny_mempool ? std::vector<const char*>{"-mempoolfullrbf=0", "-maxmempool=0"}
                           : std::vector<const char*>{"-mempoolfullrbf=0"}),
          consensus{const_cast<Consensus::Params&>(Params().GetConsensus())},
          old_nexus{consensus.nNexusStartBlock}
    {
        mineBlocks(10);
        consensus.nNexusStartBlock = 101;
    }
    ~ZdagMempoolSetup() { consensus.nNexusStartBlock = old_nexus; }

    CMutableTransaction Spend(CAmount fee, uint8_t memo,
                              const std::vector<size_t>& funding = {0},
                              uint32_t sequence = CTxIn::SEQUENCE_FINAL)
    {
        std::vector<CTransactionRef> parents;
        for (const auto index : funding) parents.push_back(m_coinbase_txns[index]);
        return SpendOutputs(parents, fee, memo, sequence);
    }

    CMutableTransaction SpendOutputs(const std::vector<CTransactionRef>& funding,
                                     CAmount fee, uint8_t memo,
                                     uint32_t sequence = CTxIn::SEQUENCE_FINAL)
    {
        CMutableTransaction tx;
        tx.nVersion = SYSCOIN_TX_VERSION_ALLOCATION_SEND;
        CAmount total{0};
        for (const auto& parent : funding) {
            tx.vin.emplace_back(COutPoint{parent->GetHash(), 0}, CScript{}, sequence);
            total += parent->vout[0].nValue;
        }
        tx.vout.emplace_back(total - fee,
                            GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())));
        // Empty asset set plus a memo: a valid allocation of ordinary SYS.
        tx.vout.emplace_back(0, CScript{} << OP_RETURN << std::vector<uint8_t>{0, memo});
        FillableSigningProvider provider;
        provider.AddKey(coinbaseKey);
        for (size_t i{0}; i < funding.size(); ++i) {
            SignatureData data;
            BOOST_REQUIRE(SignSignature(provider, *funding[i], tx, i,
                                        SIGHASH_ALL, data));
        }
        return tx;
    }

    CTransactionRef Accept(const CMutableTransaction& tx)
    {
        const auto ref{MakeTransactionRef(tx)};
        LOCK(cs_main);
        const auto result{m_node.chainman->ProcessTransaction(ref)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              result.m_state.ToString());
        return ref;
    }

    Consensus::Params& consensus;
    const int old_nexus;
};

BOOST_FIXTURE_TEST_CASE(zdag_failed_and_test_admission_leave_no_reservation,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1))};
    const COutPoint outpoint{first->vin[0].prevout};
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    BOOST_REQUIRE(!pool.m_full_rbf);
    BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().HaveCoinInCache(outpoint));

    auto missing_input{Spend(2000, 2)};
    missing_input.vin.emplace_back(COutPoint{uint256S(std::string(64, '1')), 0});
    auto bad_signature{Spend(2000, 3)};
    bad_signature.vin[0].scriptSig = CScript{} << OP_0;
    for (const auto& tx : {missing_input, bad_signature}) {
        auto ref{MakeTransactionRef(tx)};
        std::weak_ptr<const CTransaction> weak{ref};
        const auto result{m_node.chainman->ProcessTransaction(ref)};
        BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
        BOOST_CHECK_EQUAL(pool.size(), 1U);
        ref.reset();
        BOOST_CHECK(weak.expired());
    }

    const auto candidate{MakeTransactionRef(Spend(2000, 4))};
    for (int attempt{0}; attempt < 2; ++attempt) {
        const auto result{m_node.chainman->ProcessTransaction(candidate, /*test_accept=*/true)};
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                              result.m_state.ToString());
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
        BOOST_CHECK_EQUAL(pool.size(), 1U);
    }
    const auto accepted{m_node.chainman->ProcessTransaction(candidate)};
    BOOST_REQUIRE_MESSAGE(accepted.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          accepted.m_state.ToString());
    BOOST_REQUIRE_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    const auto before{ZdagMempoolTestAccess::Conflicts(pool).at(outpoint)};
    BOOST_CHECK(before.first == candidate->GetHash());
    BOOST_CHECK(before.second == first->GetHash());
    const auto third{MakeTransactionRef(Spend(3000, 5))};
    const auto rejected{m_node.chainman->ProcessTransaction(third, /*test_accept=*/true)};
    BOOST_CHECK(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).at(outpoint) == before);
    BOOST_CHECK_EQUAL(pool.size(), 2U);
}

BOOST_FIXTURE_TEST_CASE(zdag_failed_package_preserves_conflict_state,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1))};
    auto invalid{Spend(2000, 2)};
    invalid.vin[0].scriptSig = CScript{} << OP_0;
    const auto invalid_ref{MakeTransactionRef(invalid)};
    CMutableTransaction child;
    child.vin.emplace_back(COutPoint{invalid_ref->GetHash(), 0});
    child.vout.emplace_back(invalid.vout[0].nValue - 1000,
                            GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())));
    child.vin[0].scriptSig = CScript{} << std::vector<uint8_t>(72, 0);
    LOCK(cs_main);
    auto& pool{*m_node.mempool};
    LOCK(pool.cs);
    for (const bool test_accept : {false, true}) {
        const auto result{ProcessNewPackage(m_node.chainman->ActiveChainstate(), pool,
                                           {invalid_ref, MakeTransactionRef(child)}, test_accept)};
        BOOST_CHECK(!result.m_state.IsValid());
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
        BOOST_CHECK_EQUAL(pool.size(), 1U);
        BOOST_CHECK(pool.exists(GenTxid::Txid(first->GetHash())));
    }
    // Package submission is intentionally partial: retain an admitted parent
    // even when its child fails, including the parent's conflict warning.
    const auto parent{MakeTransactionRef(Spend(2000, 3))};
    child.vin[0].prevout = COutPoint{parent->GetHash(), 0};
    child.vout[0].nValue = parent->vout[0].nValue - 1000;
    const auto partial{ProcessNewPackage(m_node.chainman->ActiveChainstate(), pool,
                                        {parent, MakeTransactionRef(child)}, false)};
    BOOST_CHECK(!partial.m_state.IsValid());
    BOOST_CHECK(pool.exists(GenTxid::Txid(parent->GetHash())));
    const auto before{ZdagMempoolTestAccess::Conflicts(pool).at(first->vin[0].prevout)};
    child.vin[0].prevout = COutPoint{invalid_ref->GetHash(), 0};
    child.vout[0].nValue = invalid.vout[0].nValue - 1000;
    const auto result{ProcessNewPackage(m_node.chainman->ActiveChainstate(), pool,
                                       {invalid_ref, MakeTransactionRef(child)}, true)};
    BOOST_CHECK(!result.m_state.IsValid());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).at(first->vin[0].prevout) == before);
}

struct ZdagTinyMempoolSetup : ZdagMempoolSetup {
    ZdagTinyMempoolSetup() : ZdagMempoolSetup(true) {}

    void CheckSizeRejection(bool package)
    {
        auto& chainstate{m_node.chainman->ActiveChainstate()};
        auto& limited{*m_node.mempool};
        BOOST_REQUIRE_EQUAL(limited.m_max_size_bytes, 0);
        LOCK(cs_main);
        LOCK(limited.cs);
        // Isolate transaction-size eviction from the independent evidence cap.
        ZdagMempoolTestAccess::SetConflictCapacity(limited, 1);
        const auto first{MakeTransactionRef(Spend(10000, 1))};
        const auto initial{AcceptToMemoryPool(chainstate, first, GetTime(),
                                            /*bypass_limits=*/true, /*test_accept=*/false)};
        BOOST_REQUIRE(initial.m_result_type == MempoolAcceptResult::ResultType::VALID);
        const auto candidate{MakeTransactionRef(Spend(2000, 2))};
        if (package) {
            CMutableTransaction child;
            child.vin.emplace_back(COutPoint{candidate->GetHash(), 0});
            child.vout.emplace_back(candidate->vout[0].nValue - 1000,
                                    GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())));
            child.vin[0].scriptSig = CScript{} << std::vector<uint8_t>(72, 0);
            const auto result{ProcessNewPackage(chainstate, limited,
                                               {candidate, MakeTransactionRef(child)}, false)};
            BOOST_CHECK(!result.m_state.IsValid());
            const auto& candidate_result{result.m_tx_results.at(candidate->GetWitnessHash())};
            BOOST_CHECK(candidate_result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK_EQUAL(candidate_result.m_state.GetRejectReason(), "mempool full");
        } else {
            const auto result{AcceptToMemoryPool(chainstate, candidate, GetTime(),
                                                /*bypass_limits=*/false, /*test_accept=*/false)};
            BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "mempool full");
        }
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(limited).empty());
        BOOST_CHECK_EQUAL(limited.size(), 0U);
    }
};

BOOST_FIXTURE_TEST_CASE(zdag_immediate_size_rejection_does_not_publish,
                        ZdagTinyMempoolSetup)
{
    CheckSizeRejection(false);
}

BOOST_FIXTURE_TEST_CASE(zdag_package_size_rejection_does_not_publish,
                        ZdagTinyMempoolSetup)
{
    CheckSizeRejection(true);
}

BOOST_FIXTURE_TEST_CASE(zdag_removal_preserves_warning_and_rebinds_survivor,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1))};
    const auto second{Accept(Spend(2000, 2))};
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    BOOST_REQUIRE(pool.existsConflicts(*first));
    BOOST_REQUIRE(pool.existsConflicts(*second));
    pool.removeRecursive(*second, MemPoolRemovalReason::EXPIRY);
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.GetConflictTx(first->vin[0].prevout) == first.get());
    BOOST_CHECK(pool.existsConflicts(*first));
    const auto third{m_node.chainman->ProcessTransaction(MakeTransactionRef(Spend(2000, 3)))};
    BOOST_CHECK(third.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    pool.removeForReorg(m_node.chainman->ActiveChain(), [&](auto it) {
        return it->GetTx().GetHash() == first->GetHash();
    });
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.GetConflictTx(first->vin[0].prevout) == nullptr);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    pool.TrimToSize(0);
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.GetConflictTx(first->vin[0].prevout) == nullptr);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
}

BOOST_FIXTURE_TEST_CASE(zdag_confirmation_removes_both_spenders,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1))};
    Accept(Spend(2000, 2));
    const auto external{Spend(3000, 3)};
    const CBlock block{CreateAndProcessBlock({external},
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())))};
    LOCK(cs_main);
    auto& pool{*m_node.mempool};
    LOCK(pool.cs);
    BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
    BOOST_CHECK(pool.GetConflictTx(first->vin[0].prevout) == nullptr);
    BOOST_CHECK_EQUAL(pool.size(), 0U);
}

BOOST_FIXTURE_TEST_CASE(zdag_multi_input_removal_preserves_every_survivor,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1, {0, 1}))};
    const auto second{Accept(Spend(2000, 2, {0, 1}))};
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    BOOST_REQUIRE_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 2U);
    pool.removeRecursive(*first, MemPoolRemovalReason::SIZELIMIT);
    for (const auto& input : second->vin) {
        BOOST_CHECK(pool.GetConflictTx(input.prevout) == second.get());
        BOOST_CHECK(pool.GetZDAGConflict(input.prevout).has_value());
    }
    BOOST_CHECK(pool.existsConflicts(*second));
    // The known first spender can confirm even after eviction. Both rows
    // and the surviving conflicting transaction must then be removed.
    pool.removeForBlock({first}, 111);
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    for (const auto& input : second->vin) {
        BOOST_CHECK(pool.GetConflictTx(input.prevout) == nullptr);
    }
}

BOOST_FIXTURE_TEST_CASE(zdag_multiple_incumbents_keep_input_indexes_consistent,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1, {0}))};
    SetMockTime(GetTime() + 1);
    const auto other{Accept(Spend(1000, 2, {1}))};
    SetMockTime(GetTime() + 1);
    const auto combined{Accept(Spend(2000, 3, {1, 0}))};
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    BOOST_REQUIRE_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 2U);
    pool.removeRecursive(*other, MemPoolRemovalReason::REORG);
    // A sole surviving first input must not hide the older spender of the
    // second input from the miner's conflict selection.
    BOOST_CHECK(!pool.isSyscoinConflictIsFirstSeen(*combined));
    BOOST_CHECK(pool.isSyscoinConflictIsFirstSeen(*first));
    pool.removeRecursive(*first, MemPoolRemovalReason::EXPIRY);
    BOOST_CHECK(pool.isSyscoinConflictIsFirstSeen(*combined));
    for (const auto& input : combined->vin) {
        BOOST_CHECK(pool.GetConflictTx(input.prevout) == combined.get());
        BOOST_CHECK(pool.GetZDAGConflict(input.prevout).has_value());
    }
    pool.removeForBlock({combined}, 111);
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
    BOOST_CHECK_EQUAL(pool.size(), 0U);
}

BOOST_FIXTURE_TEST_CASE(zdag_evicted_evidence_is_compact_and_allows_only_recorded_spenders,
                        ZdagMempoolSetup)
{
    const auto first_tx{Spend(1000, 1)};
    const auto second_tx{Spend(2000, 2)};
    auto first{Accept(first_tx)};
    auto second{Accept(second_tx)};
    const COutPoint outpoint{first->vin[0].prevout};
    std::weak_ptr<const CTransaction> first_weak{first};
    std::weak_ptr<const CTransaction> second_weak{second};
    auto& pool{*m_node.mempool};
    {
        LOCK(cs_main);
        LOCK(pool.cs);
        pool.TrimToSize(0);
        BOOST_CHECK_EQUAL(pool.size(), 0U);
        BOOST_REQUIRE(pool.GetZDAGConflict(outpoint).has_value());
    }
    SyncWithValidationInterfaceQueue();
    first.reset();
    second.reset();
    BOOST_CHECK(first_weak.expired());
    BOOST_CHECK(second_weak.expired());
    {
        LOCK(cs_main);
        const auto third{m_node.chainman->ProcessTransaction(MakeTransactionRef(Spend(3000, 3)))};
        BOOST_CHECK(third.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(third.m_state.GetRejectReason(), "txn-mempool-conflict-zdag");
        // Bypass only the fee floor raised by the explicit trim above.
        for (const auto& tx : {first_tx, second_tx}) {
            const auto restored{AcceptToMemoryPool(m_node.chainman->ActiveChainstate(),
                MakeTransactionRef(tx), GetTime(), true, false)};
            BOOST_REQUIRE_MESSAGE(restored.m_result_type == MempoolAcceptResult::ResultType::VALID,
                                  restored.m_state.ToString());
        }
        LOCK(pool.cs);
        BOOST_CHECK_EQUAL(pool.size(), 2U);
        BOOST_CHECK(pool.existsConflicts(CTransaction{first_tx}));
        pool.check(m_node.chainman->ActiveChainstate().CoinsTip(), 111);
    }
}

BOOST_FIXTURE_TEST_CASE(zdag_trimmed_incumbent_does_not_erase_new_warning,
                        ZdagMempoolSetup)
{
    const auto first{Accept(Spend(1000, 1))};
    const auto candidate{MakeTransactionRef(Spend(2000, 2))};
    const COutPoint outpoint{first->vin[0].prevout};
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    // Reproduce the state between insertion and post-trim publication.
    TestMemPoolEntryHelper entry;
    BOOST_REQUIRE(pool.addUnchecked(entry.Fee(2000).SpendsCoinbase(true).FromTx(candidate)));
    pool.removeRecursive(*first, MemPoolRemovalReason::SIZELIMIT);
    BOOST_CHECK(!pool.GetZDAGConflict(outpoint).has_value());
    pool.RegisterZDAGConflict(outpoint, candidate->GetHash(), first->GetHash());
    BOOST_REQUIRE(pool.GetZDAGConflict(outpoint).has_value());
    BOOST_CHECK(pool.existsConflicts(*candidate));
    BOOST_CHECK(pool.GetConflictTx(outpoint) == candidate.get());
}

BOOST_FIXTURE_TEST_CASE(zdag_evidence_cap_requires_authentication_and_real_admission,
                        ZdagMempoolSetup)
{
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    const size_t default_capacity{static_cast<size_t>(pool.m_max_size_bytes) /
                                  10 / pool.ZDAGConflictMemoryUsage(1)};
    BOOST_CHECK(pool.HasZDAGConflictCapacity(default_capacity));
    BOOST_CHECK(!pool.HasZDAGConflictCapacity(default_capacity + 1));
    ZdagMempoolTestAccess::SetConflictCapacity(pool, 1);
    const auto first{Accept(Spend(1000, 1))};
    const auto second{Accept(Spend(2000, 2))};
    const auto other{Accept(Spend(1000, 3, {1}))};
    const auto evidence{ZdagMempoolTestAccess::Conflicts(pool)};
    const auto memory_usage{pool.DynamicMemoryUsage()};
    BOOST_REQUIRE_EQUAL(evidence.size(), 1U);
    BOOST_CHECK(!pool.HasZDAGConflictCapacity(1));
    BOOST_CHECK(!pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, other->GetHash()), ZDAG_STATUS_OK);
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, first->GetHash()), ZDAG_MAJOR_CONFLICT);

    auto bad_signature{Spend(2000, 4, {1})};
    bad_signature.vin[0].scriptSig = CScript{} << OP_0;
    const auto invalid{MakeTransactionRef(bad_signature)};
    const auto invalid_child{MakeTransactionRef(SpendOutputs({invalid}, 1000, 5))};
    for (const bool test_accept : {false, true}) {
        const auto rejected{m_node.chainman->ProcessTransaction(invalid, test_accept)};
        BOOST_CHECK(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK(rejected.m_state.GetRejectReason() != "zdag-conflict-evidence-full");
        const auto package{ProcessNewPackage(m_node.chainman->ActiveChainstate(), pool,
                                             {invalid, invalid_child}, test_accept)};
        BOOST_CHECK(!package.m_state.IsValid());
        BOOST_CHECK(!pool.IsZDAGVerificationIncomplete());
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
        BOOST_CHECK_EQUAL(pool.size(), 3U);
        BOOST_CHECK_EQUAL(pool.DynamicMemoryUsage(), memory_usage);
        BOOST_CHECK(pool.GetConflictTx(other->vin[0].prevout) == other.get());
    }

    const auto candidate{MakeTransactionRef(Spend(2000, 6, {1}))};
    const auto dry_run{m_node.chainman->ProcessTransaction(candidate, /*test_accept=*/true)};
    BOOST_CHECK(dry_run.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(dry_run.m_state.GetRejectReason(), "zdag-conflict-evidence-full");
    BOOST_CHECK(!pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
    BOOST_CHECK_EQUAL(pool.DynamicMemoryUsage(), memory_usage);

    const auto rejected{m_node.chainman->ProcessTransaction(candidate)};
    BOOST_CHECK(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "zdag-conflict-evidence-full");
    BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
    BOOST_CHECK_EQUAL(pool.size(), 3U);
    BOOST_CHECK_EQUAL(pool.DynamicMemoryUsage(), memory_usage);
    BOOST_CHECK(pool.GetConflictTx(other->vin[0].prevout) == other.get());
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, first->GetHash()), ZDAG_MAJOR_CONFLICT);
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, second->GetHash()), ZDAG_MAJOR_CONFLICT);
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, other->GetHash()), ZDAG_WARNING_VERIFICATION_INCOMPLETE);
    const auto unrelated{Accept(Spend(1000, 7, {2}))};
    BOOST_CHECK_EQUAL(pool.size(), 4U);
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, unrelated->GetHash()), ZDAG_WARNING_VERIFICATION_INCOMPLETE);
}

BOOST_FIXTURE_TEST_CASE(zdag_evidence_cap_reserves_all_inputs_before_mutating_pool,
                        ZdagMempoolSetup)
{
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    ZdagMempoolTestAccess::SetConflictCapacity(pool, 1);
    const auto first{Accept(Spend(1000, 1, {0, 1}))};
    const auto candidate{MakeTransactionRef(Spend(2000, 2, {0, 1}))};
    const auto memory_usage{pool.DynamicMemoryUsage()};
    const auto rejected{m_node.chainman->ProcessTransaction(candidate)};
    BOOST_CHECK(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK_EQUAL(rejected.m_state.GetRejectReason(), "zdag-conflict-evidence-full");
    BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
    BOOST_CHECK_EQUAL(pool.size(), 1U);
    BOOST_CHECK_EQUAL(pool.DynamicMemoryUsage(), memory_usage);
    for (const auto& input : first->vin) {
        BOOST_CHECK(pool.GetConflictTx(input.prevout) == first.get());
    }
    // A failed two-input reservation must not consume the one available slot.
    const auto one_input{Accept(Spend(2000, 3, {0}))};
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.GetZDAGConflict(first->vin[0].prevout).has_value());
    BOOST_CHECK(!pool.GetZDAGConflict(first->vin[1].prevout).has_value());
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, one_input->GetHash()), ZDAG_MAJOR_CONFLICT);
    pool.check(m_node.chainman->ActiveChainstate().CoinsTip(), 111);
}

BOOST_FIXTURE_TEST_CASE(zdag_evidence_cap_retains_pairs_and_recovers_only_after_confirmation,
                        ZdagMempoolSetup)
{
    auto& pool{*m_node.mempool};
    const auto first_tx{Spend(1000, 1)};
    const auto second_tx{Spend(2000, 2)};
    const auto first{Accept(first_tx)};
    const auto second{Accept(second_tx)};
    const auto other{Accept(Spend(1000, 3, {1}))};
    {
        LOCK(cs_main);
        LOCK(pool.cs);
        ZdagMempoolTestAccess::SetConflictCapacity(pool, 1);
        const auto rejected{m_node.chainman->ProcessTransaction(MakeTransactionRef(Spend(2000, 4, {1})))};
        BOOST_REQUIRE(rejected.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_REQUIRE(pool.IsZDAGVerificationIncomplete());
        const auto evidence{ZdagMempoolTestAccess::Conflicts(pool)};
        pool.TrimToSize(0);
        BOOST_CHECK_EQUAL(pool.size(), 0U);
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
        BOOST_CHECK(!pool.HasZDAGConflictCapacity(1));
        // Only bypass the fee floor raised by TrimToSize. Capacity still applies.
        for (const auto& tx : {first, second}) {
            const auto restored{AcceptToMemoryPool(m_node.chainman->ActiveChainstate(),
                                                   tx, GetTime(), true, false)};
            BOOST_REQUIRE_MESSAGE(restored.m_result_type == MempoolAcceptResult::ResultType::VALID,
                                  restored.m_state.ToString());
            BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, tx->GetHash()), ZDAG_MAJOR_CONFLICT);
        }
        const auto third{AcceptToMemoryPool(m_node.chainman->ActiveChainstate(),
            MakeTransactionRef(Spend(3000, 5)), GetTime(), true, false)};
        BOOST_CHECK(third.m_result_type == MempoolAcceptResult::ResultType::INVALID);
        BOOST_CHECK_EQUAL(third.m_state.GetRejectReason(), "txn-mempool-conflict-zdag");
        BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool) == evidence);
    }

    const CBlock block{CreateAndProcessBlock({first_tx},
        GetScriptForDestination(PKHash(coinbaseKey.GetPubKey())))};
    LOCK(cs_main);
    LOCK(pool.cs);
    BOOST_REQUIRE(m_node.chainman->ActiveTip()->GetBlockHash() == block.GetHash());
    BOOST_CHECK(ZdagMempoolTestAccess::Conflicts(pool).empty());
    BOOST_CHECK(pool.HasZDAGConflictCapacity(1));
    BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK_EQUAL(pool.size(), 0U);
    const auto restored{AcceptToMemoryPool(m_node.chainman->ActiveChainstate(),
                                           other, GetTime(), true, false)};
    BOOST_REQUIRE_MESSAGE(restored.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          restored.m_state.ToString());
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, other->GetHash()), ZDAG_WARNING_VERIFICATION_INCOMPLETE);
    const auto new_pair{AcceptToMemoryPool(m_node.chainman->ActiveChainstate(),
        MakeTransactionRef(Spend(2000, 6, {1})), GetTime(), true, false)};
    BOOST_REQUIRE_MESSAGE(new_pair.m_result_type == MempoolAcceptResult::ResultType::VALID,
                          new_pair.m_state.ToString());
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
    BOOST_CHECK_EQUAL(CheckActorsInTransactionGraph(pool, other->GetHash()), ZDAG_MAJOR_CONFLICT);
}

BOOST_FIXTURE_TEST_CASE(zdag_evidence_cap_counts_deferred_package_conflicts,
                        ZdagMempoolSetup)
{
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    ZdagMempoolTestAccess::SetConflictCapacity(pool, 1);
    const auto first{Accept(Spend(1000, 1, {0}))};
    const auto other{Accept(Spend(1000, 2, {1}))};
    const auto candidate{MakeTransactionRef(Spend(2000, 3, {0}))};
    const auto excess{MakeTransactionRef(Spend(2000, 4, {1}))};
    const auto child{MakeTransactionRef(SpendOutputs({candidate, excess}, 2000, 5))};
    const auto result{ProcessNewPackage(m_node.chainman->ActiveChainstate(), pool,
                                        {candidate, excess, child}, false)};
    BOOST_CHECK(!result.m_state.IsValid());
    // The first parent is accepted before its evidence is published; the second
    // must see that pending reservation even though the map is still empty.
    BOOST_CHECK(result.m_tx_results.at(candidate->GetWitnessHash()).m_result_type ==
                MempoolAcceptResult::ResultType::VALID);
    BOOST_CHECK(result.m_tx_results.at(excess->GetWitnessHash()).m_result_type ==
                MempoolAcceptResult::ResultType::INVALID);
    BOOST_CHECK(pool.exists(GenTxid::Txid(candidate->GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(excess->GetHash())));
    BOOST_CHECK(!pool.exists(GenTxid::Txid(child->GetHash())));
    BOOST_CHECK_EQUAL(pool.size(), 3U);
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), 1U);
    BOOST_CHECK(pool.GetZDAGConflict(first->vin[0].prevout).has_value());
    BOOST_CHECK(!pool.GetZDAGConflict(other->vin[0].prevout).has_value());
    BOOST_CHECK(pool.GetConflictTx(other->vin[0].prevout) == other.get());
    BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
    pool.check(m_node.chainman->ActiveChainstate().CoinsTip(), 111);
}

BOOST_FIXTURE_TEST_CASE(zdag_evidence_cap_bounds_repeated_unconfirmed_parent_replacement,
                        ZdagMempoolSetup)
{
    auto& pool{*m_node.mempool};
    LOCK(cs_main);
    LOCK(pool.cs);
    constexpr size_t capacity{3};
    ZdagMempoolTestAccess::SetConflictCapacity(pool, capacity);
    std::vector<COutPoint> retained_outpoints;
    CTransactionRef previous_parent;
    for (size_t round{0}; round < capacity + 2; ++round) {
        // Replacing the RBF parent removes both child spenders but cannot erase
        // their evidence: the parent remains unconfirmed and may return later.
        const auto parent{Accept(Spend(100000 * (round + 1), static_cast<uint8_t>(round),
                                       {0}, CTxIn::SEQUENCE_FINAL - 2))};
        if (previous_parent) BOOST_CHECK(!pool.exists(GenTxid::Txid(previous_parent->GetHash())));
        const auto first{Accept(SpendOutputs({parent}, 1000, 10))};
        const auto second{MakeTransactionRef(SpendOutputs({parent}, 2000, 11))};
        const auto result{m_node.chainman->ProcessTransaction(second)};
        if (round < capacity) {
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                                  result.m_state.ToString());
            retained_outpoints.push_back(first->vin[0].prevout);
            BOOST_CHECK_EQUAL(pool.size(), 3U);
            BOOST_CHECK(!pool.IsZDAGVerificationIncomplete());
        } else {
            BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);
            BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "zdag-conflict-evidence-full");
            BOOST_CHECK_EQUAL(pool.size(), 2U);
            BOOST_CHECK(pool.GetConflictTx(first->vin[0].prevout) == first.get());
            BOOST_CHECK(!pool.GetZDAGConflict(first->vin[0].prevout).has_value());
            BOOST_CHECK(pool.IsZDAGVerificationIncomplete());
        }
        BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), retained_outpoints.size());
        for (const auto& outpoint : retained_outpoints) {
            BOOST_CHECK(pool.GetZDAGConflict(outpoint).has_value());
        }
        previous_parent = parent;
    }
    BOOST_CHECK_EQUAL(ZdagMempoolTestAccess::Conflicts(pool).size(), capacity);
    BOOST_CHECK(!pool.HasZDAGConflictCapacity(1));
    pool.check(m_node.chainman->ActiveChainstate().CoinsTip(), 111);
}
// SYSCOIN END: Cover authenticated ZDAG admission, retention, limits, and warning precedence.
BOOST_AUTO_TEST_SUITE_END()
