// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <test/util/setup_common.h>

#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <validation.h>
#include <base58.h>
#include <consensus/validation.h>
#include <netbase.h>
#include <messagesigner.h>
#include <masternode/masternodepayments.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <random.h>
#include <script/signingprovider.h>
#include <spork.h>
#include <txmempool.h>

#include <evo/specialtx.h>
#include <evo/providertx.h>
#include <evo/providertx_signaturecache.h>
#include <evo/deterministicmns.h>
#include <governance/governance.h>
#include <governance/governanceclasses.h>
#include <governance/governanceexceptions.h>
#include <governance/governancevote.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <chainparams.h>
#include <dbwrapper.h>
#include <protocol.h>
#include <streams.h>
#include <boost/test/unit_test.hpp>
#include <test/util/txmempool.h>
#include <interfaces/chain.h>
#include <util/time.h>

using SimpleUTXOVec = std::vector<std::pair<COutPoint, std::pair<int, CAmount>> >;

static SimpleUTXOVec BuildSimpleUTXOVec(const std::vector<CTransactionRef>& txs)
{
    SimpleUTXOVec utxos;
    for (size_t i = 0; i < txs.size(); i++) {
        auto& tx = *txs[i];
        for (size_t j = 0; j < tx.vout.size(); j++) {
            if(tx.vout[j].nValue > 0)
                utxos.emplace_back(COutPoint(tx.GetHash(), j), std::make_pair((int)i + 1, tx.vout[j].nValue));
        }
    }
    return utxos;
}

static std::vector<COutPoint> SelectUTXOs(const node::NodeContext& node, SimpleUTXOVec& utxos, CAmount amount, CAmount& changeRet)
{
    changeRet = 0;
    std::vector<COutPoint> selectedUtxos;
    CAmount selectedAmount = 0;
    auto it = utxos.begin();
    bool bFound = false;
    while (it != utxos.end()) {
        if (*node.chain->getHeight() - it->second.first < 101) {
            it++;
            continue;
        }
        selectedAmount += it->second.second;
        selectedUtxos.emplace_back(it->first);
        it = utxos.erase(it);
        bFound = true;
        if (selectedAmount >= amount) {
            changeRet = selectedAmount - amount;
            break;
        }
    }
    assert(bFound);
    return selectedUtxos;
}

static void FundTransaction(const node::NodeContext& node, CMutableTransaction& tx, SimpleUTXOVec& utoxs, const CScript& scriptPayout, CAmount amount)
{
    CAmount change;
    auto inputs = SelectUTXOs(node, utoxs, amount, change);
    for (size_t i = 0; i < inputs.size(); i++) {
        tx.vin.emplace_back(CTxIn(inputs[i]));
    }
    tx.vout.emplace_back(CTxOut(amount, scriptPayout));
    if (change != 0) {
        tx.vout.emplace_back(CTxOut(change, scriptPayout));
    }
}

static void SignTransaction(const node::NodeContext& node, CMutableTransaction& tx, const CKey& coinbaseKey)
{
    LOCK(cs_main);
    FillableSigningProvider tempKeystore;
    tempKeystore.AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
    std::map<COutPoint, Coin> coins;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        coins[tx.vin[i].prevout]; 
        node.chain->findCoins(coins);
    }
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(tx, &tempKeystore, coins, SIGHASH_ALL, input_errors));
}

static CMutableTransaction CreateProRegTx(const node::NodeContext& node, SimpleUTXOVec& utxos, int port, const CScript& scriptPayout, const CKey& coinbaseKey, CKey& ownerKeyRet, CBLSSecretKey& operatorKeyRet)
{
    ownerKeyRet.MakeNewKey(true);
    operatorKeyRet.MakeNewKey();

    CProRegTx proTx;
    proTx.nVersion = CProRegTx::GetVersion(!bls::bls_legacy_scheme);
    proTx.collateralOutpoint.n = 0;
    proTx.addr = LookupNumeric("1.1.1.1", port);
    proTx.keyIDOwner = ownerKeyRet.GetPubKey().GetID();
    proTx.pubKeyOperator.Set(operatorKeyRet.GetPublicKey(), bls::bls_legacy_scheme.load());
    proTx.keyIDVoting = ownerKeyRet.GetPubKey().GetID();
    proTx.scriptPayout = scriptPayout;
    proTx.nOperatorReward = 5000;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    FundTransaction(node, tx, utxos, scriptPayout, 100 * COIN);
    proTx.inputsHash = CalcTxInputsHash(CTransaction(tx));
    SetTxPayload(tx, proTx);
    SignTransaction(node, tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpServTx(const node::NodeContext& node, SimpleUTXOVec& utxos, const uint256& proTxHash, const CBLSSecretKey& operatorKey, int port, const CKey& coinbaseKey)
{
    CProUpServTx proTx;
    proTx.nVersion = CProUpRevTx::GetVersion(!bls::bls_legacy_scheme);
    proTx.proTxHash = proTxHash;
    proTx.addr = LookupNumeric("1.1.1.1", port);
    proTx.scriptOperatorPayout = GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey()));
    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE;
    FundTransaction(node, tx, utxos, GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey())), 1 * COIN);
    proTx.inputsHash = CalcTxInputsHash(CTransaction(tx));
    proTx.sig = operatorKey.Sign(::SerializeHash(proTx), bls::bls_legacy_scheme);
    SetTxPayload(tx, proTx);
    SignTransaction(node, tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpRegTx(const node::NodeContext& node, SimpleUTXOVec& utxos, const uint256& proTxHash, const CKey& mnKey, const CBLSPublicKey& pubKeyOperator, const CKeyID& keyIDVoting, const CScript& scriptPayout, const CKey& coinbaseKey)
{

    CProUpRegTx proTx;
    proTx.nVersion = CProUpRegTx::GetVersion(!bls::bls_legacy_scheme);
    proTx.proTxHash = proTxHash;
    proTx.pubKeyOperator.Set(pubKeyOperator, bls::bls_legacy_scheme.load());
    proTx.keyIDVoting = keyIDVoting;
    proTx.scriptPayout = scriptPayout;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
    FundTransaction(node, tx, utxos, GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey())), 1 * COIN);
    proTx.inputsHash = CalcTxInputsHash(CTransaction(tx));
    CHashSigner::SignHash(::SerializeHash(proTx), mnKey, proTx.vchSig);
    SetTxPayload(tx, proTx);
    SignTransaction(node, tx, coinbaseKey);

    return tx;
}

static CMutableTransaction CreateProUpRevTx(const node::NodeContext& node, SimpleUTXOVec& utxos, const uint256& proTxHash, const CBLSSecretKey& operatorKey, const CKey& coinbaseKey)
{
    CProUpRevTx proTx;
    proTx.nVersion = CProUpRevTx::GetVersion(!bls::bls_legacy_scheme);
    proTx.proTxHash = proTxHash;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE;
    FundTransaction(node, tx, utxos, GetScriptForDestination(WitnessV0KeyHash(coinbaseKey.GetPubKey())), 1 * COIN);
    proTx.inputsHash = CalcTxInputsHash(CTransaction(tx));
    proTx.sig = operatorKey.Sign(::SerializeHash(proTx), bls::bls_legacy_scheme);
    SetTxPayload(tx, proTx);
    SignTransaction(node, tx, coinbaseKey);

    return tx;
}

template<typename ProTx>
static CMutableTransaction MalleateProTxPayout(const CMutableTransaction& tx)
{
    ProTx proTx;
    GetTxPayload(tx, proTx);

    CKey key;
    key.MakeNewKey(true);
    proTx.scriptPayout = GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));

    CMutableTransaction tx2 = tx;
    SetTxPayload(tx2, proTx);

    return tx2;
}

static CScript GenerateRandomAddress()
{
    CKey key;
    key.MakeNewKey(true);
    return GetScriptForDestination(WitnessV0KeyHash(key.GetPubKey()));
}

static CDeterministicMNCPtr FindPayoutDmn(const CBlock& block)
{
    auto mnList = deterministicMNManager->GetListAtChainTip();

    for (const auto& txout : block.vtx[0]->vout) {
        CDeterministicMNCPtr found;
        mnList.ForEachMNShared(true, [&](const CDeterministicMNCPtr& dmn) {
            if (found == nullptr && txout.scriptPubKey == dmn->pdmnState->scriptPayout) {
                found = dmn;
            }
        });
        if (found != nullptr) {
            return found;
        }
    }
    return nullptr;
}

static bool CheckTransactionSignature(const node::NodeContext& node, const CMutableTransaction& tx)
{
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const auto& txin = tx.vin[i];
        std::map<COutPoint, Coin> coins;
        coins[txin.prevout]; 
        node.chain->findCoins(coins);
        const Coin& coin = coins.at(txin.prevout);
        if (!VerifyScript(txin.scriptSig, coin.out.scriptPubKey, nullptr, STANDARD_SCRIPT_VERIFY_FLAGS, MutableTransactionSignatureChecker(&tx, i, coin.out.nValue, MissingDataBehavior::ASSERT_FAIL))) {
            return false;
        }
    }
    return true;
}

static uint256 MakeSnapshotKey(int height)
{
    return ArithToUint256(arith_uint256(height + 1));
}

static CDeterministicMNList MakeSnapshot(int height)
{
    const uint256 block_hash = MakeSnapshotKey(height);
    return CDeterministicMNList(block_hash, height, 0);
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

void FuncDIP3Activation(TestChain100Setup& setup)
{
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    CKey ownerKey;
    CBLSSecretKey operatorKey;
    CScript addr = GenerateRandomAddress();
    auto tx = CreateProRegTx(setup.m_node, utxos, 1, addr, setup.coinbaseKey, ownerKey, operatorKey);
    std::vector<CMutableTransaction> txns = std::vector<CMutableTransaction>{tx};

    int nHeight = *setup.m_node.chain->getHeight();

    // We start one block before DIP3 activation, so mining a block with a DIP3 transaction should be no-op
    auto block = std::make_shared<CBlock>(setup.CreateAndProcessBlock(txns, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey())));
 
    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
    BOOST_CHECK_EQUAL(block->GetHash() , setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));
    
    assert(!deterministicMNManager->GetListAtChainTip().HasMN(tx.GetHash()));

    // re-create reg tx prev one got mined as no-op
    tx = CreateProRegTx(setup.m_node, utxos, 1, addr, setup.coinbaseKey, ownerKey, operatorKey);
    txns = std::vector<CMutableTransaction>{tx};
    // Mining a block with a DIP3 transaction should succeed now
    block = std::make_shared<CBlock>(setup.CreateAndProcessBlock(txns, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey())));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 2);
    BOOST_CHECK_EQUAL(block->GetHash() , setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));
    
    assert(deterministicMNManager->GetListAtChainTip().HasMN(tx.GetHash()));
}

void FuncDIP3Protx(TestChain100Setup& setup)
{
    CKey sporkKey;
    sporkKey.MakeNewKey(true);
    sporkManager->SetSporkAddress(EncodeDestination(PKHash(sporkKey.GetPubKey())));
    sporkManager->SetPrivKey(EncodeSecret(sporkKey));

    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);

    int nHeight = *setup.m_node.chain->getHeight();
    int port = 1;

    std::vector<uint256> dmnHashes;
    std::map<uint256, CKey> ownerKeys;
    std::map<uint256, CBLSSecretKey> operatorKeys;

    // register one MN per block
    for (size_t i = 0; i < 6; i++) {
        CKey ownerKey;
        CBLSSecretKey operatorKey;
        auto tx = CreateProRegTx(setup.m_node, utxos, port++, GenerateRandomAddress(), setup.coinbaseKey, ownerKey, operatorKey);
        dmnHashes.emplace_back(tx.GetHash());
        ownerKeys.emplace(tx.GetHash(), ownerKey);
        operatorKeys.emplace(tx.GetHash(), operatorKey);
        {
            LOCK(cs_main);
            // also verify that payloads are not malleable after they have been signed
            // the form of ProRegTx we use here is one with a collateral included, so there is no signature inside the
            // payload itself. This means, we need to rely on script verification, which takes the hash of the extra payload
            // into account
            auto tx2 = MalleateProTxPayout<CProRegTx>(tx);
            TxValidationState dummyState;
            // Technically, the payload is still valid...
            assert(CheckProRegTx(CTransaction(tx), setup.m_node.chainman->ActiveTip(), dummyState, setup.m_node.chainman->ActiveChainstate().CoinsTip(), false, true));
            assert(CheckProRegTx(CTransaction(tx2), setup.m_node.chainman->ActiveTip(), dummyState, setup.m_node.chainman->ActiveChainstate().CoinsTip(), false, true));
            // But the signature should not verify anymore
            assert(CheckTransactionSignature(setup.m_node, tx));
            assert(!CheckTransactionSignature(setup.m_node, tx2));
        }

        setup.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

        BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
        
        auto mnList = deterministicMNManager->GetListAtChainTip();
        assert(mnList.HasMN(tx.GetHash()));

        nHeight++;
    }
    int DIP0003EnforcementHeightBackup = Params().GetConsensus().DIP0003EnforcementHeight;
    const_cast<Consensus::Params&>(Params().GetConsensus()).DIP0003EnforcementHeight = *setup.m_node.chain->getHeight() + 1;
    
    setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    nHeight++;

    // check MN reward payments
    for (size_t i = 0; i < 20; i++) {
        auto mnList = deterministicMNManager->GetListAtChainTip();
        auto dmnExpectedPayee = mnList.GetMNPayee();

        CBlock block = setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

        assert(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        assert(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }

    // register multiple MNs per block
    for (size_t i = 0; i < 3; i++) {
        std::vector<CMutableTransaction> txns;
        for (size_t j = 0; j < 3; j++) {
            CKey ownerKey;
            CBLSSecretKey operatorKey;
            auto tx = CreateProRegTx(setup.m_node, utxos, port++, GenerateRandomAddress(), setup.coinbaseKey, ownerKey, operatorKey);
            dmnHashes.emplace_back(tx.GetHash());
            ownerKeys.emplace(tx.GetHash(), ownerKey);
            operatorKeys.emplace(tx.GetHash(), operatorKey);
            txns.emplace_back(tx);
        }
        setup.CreateAndProcessBlock(txns, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));


        for (size_t j = 0; j < 3; j++) {
            assert(deterministicMNManager->GetListAtChainTip().HasMN(txns[j].GetHash()));
        }

        nHeight++;
    }

    // test ProUpServTx
    auto tx = CreateProUpServTx(setup.m_node, utxos, dmnHashes[0], operatorKeys[dmnHashes[0]], 1000, setup.coinbaseKey);
    setup.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
    nHeight++;
    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    assert(dmn != nullptr && dmn->pdmnState->addr.GetPort() == 1000);

    // test ProUpRevTx
    tx = CreateProUpRevTx(setup.m_node, utxos, dmnHashes[0], operatorKeys[dmnHashes[0]], setup.coinbaseKey);
    setup.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
    
    nHeight++;
    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    assert(dmn != nullptr && dmn->pdmnState->GetBannedHeight() == nHeight);

    // test that the revoked MN does not get paid anymore
    for (size_t i = 0; i < 20; i++) {
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();
        assert(dmnExpectedPayee->proTxHash != dmnHashes[0]);

        CBlock block = setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

        assert(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        assert(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }

    // test reviving the MN
    CBLSSecretKey newOperatorKey;
    newOperatorKey.MakeNewKey();
    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    tx = CreateProUpRegTx(setup.m_node, utxos, dmnHashes[0], ownerKeys[dmnHashes[0]], newOperatorKey.GetPublicKey(), ownerKeys[dmnHashes[0]].GetPubKey().GetID(), dmn->pdmnState->scriptPayout, setup.coinbaseKey);
    {
        LOCK(cs_main);
        // check malleability protection again, but this time by also relying on the signature inside the ProUpRegTx
        auto tx2 = MalleateProTxPayout<CProUpRegTx>(tx);
        TxValidationState dummyState;
        assert(CheckProUpRegTx(CTransaction(tx), setup.m_node.chainman->ActiveTip(), dummyState, setup.m_node.chainman->ActiveChainstate().CoinsTip(), false, true));
        assert(!CheckProUpRegTx(CTransaction(tx2), setup.m_node.chainman->ActiveTip(), dummyState, setup.m_node.chainman->ActiveChainstate().CoinsTip(), false, true));
        assert(CheckTransactionSignature(setup.m_node, tx));
        assert(!CheckTransactionSignature(setup.m_node, tx2));
    }
    // now process the block
    setup.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
    nHeight++;

    tx = CreateProUpServTx(setup.m_node, utxos, dmnHashes[0], newOperatorKey, 100, setup.coinbaseKey);
    setup.CreateAndProcessBlock({tx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 1);
    nHeight++;
    dmn = deterministicMNManager->GetListAtChainTip().GetMN(dmnHashes[0]);
    assert(dmn != nullptr && dmn->pdmnState->addr.GetPort() == 100);
    assert(dmn != nullptr && !dmn->pdmnState->IsBanned());

    // test that the revived MN gets payments again
    bool foundRevived = false;
    for (size_t i = 0; i < 20; i++) {
        auto dmnExpectedPayee = deterministicMNManager->GetListAtChainTip().GetMNPayee();
        if (dmnExpectedPayee->proTxHash == dmnHashes[0]) {
            foundRevived = true;
        }

        CBlock block = setup.CreateAndProcessBlock({}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

        assert(!block.vtx.empty());

        auto dmnPayout = FindPayoutDmn(block);
        assert(dmnPayout != nullptr);
        BOOST_CHECK_EQUAL(dmnPayout->proTxHash.ToString(), dmnExpectedPayee->proTxHash.ToString());

        nHeight++;
    }
    assert(foundRevived);

    const_cast<Consensus::Params&>(Params().GetConsensus()).DIP0003EnforcementHeight = DIP0003EnforcementHeightBackup;
}

void FuncTestMempoolReorg(TestChain100Setup& setup)
{
    int nHeight = *setup.m_node.chain->getHeight();
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    CKey ownerKey;
    CKey payoutKey;
    CKey collateralKey;
    CBLSSecretKey operatorKey;

    ownerKey.MakeNewKey(true);
    payoutKey.MakeNewKey(true);
    collateralKey.MakeNewKey(true);
    operatorKey.MakeNewKey();

    auto scriptPayout = GetScriptForDestination(WitnessV0KeyHash(payoutKey.GetPubKey()));
    auto scriptCollateral = GetScriptForDestination(WitnessV0KeyHash(collateralKey.GetPubKey()));

    // Create a MN with an external collateral
    CMutableTransaction tx_collateral;
    FundTransaction(setup.m_node, tx_collateral, utxos, scriptCollateral, 100 * COIN);
    SignTransaction(setup.m_node, tx_collateral, setup.coinbaseKey);

    auto block = setup.CreateAndProcessBlock({tx_collateral}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*(setup.m_node.chain->getHeight()) , nHeight + 1);
    BOOST_CHECK_EQUAL(block.GetHash() , setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));

    CProRegTx payload;
    payload.addr = LookupNumeric("1.1.1.1", 1);
    payload.keyIDOwner = ownerKey.GetPubKey().GetID();
    payload.pubKeyOperator.Set(operatorKey.GetPublicKey(), bls::bls_legacy_scheme.load());
    payload.keyIDVoting = ownerKey.GetPubKey().GetID();
    payload.scriptPayout = scriptPayout;

    for (size_t i = 0; i < tx_collateral.vout.size(); ++i) {
        if (tx_collateral.vout[i].nValue == 100 * COIN) {
            payload.collateralOutpoint = COutPoint(tx_collateral.GetHash(), i);
            break;
        }
    }

    CMutableTransaction tx_reg;
    tx_reg.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    FundTransaction(setup.m_node, tx_reg, utxos, scriptPayout, 100 * COIN);
    payload.inputsHash = CalcTxInputsHash(CTransaction(tx_reg));
    CMessageSigner::SignMessage(payload.MakeSignString(), payload.vchSig, collateralKey);
    SetTxPayload(tx_reg, payload);
    SignTransaction(setup.m_node, tx_reg, setup.coinbaseKey);

    CTxMemPool testPool{MemPoolOptionsForTest(setup.m_node)};
    TestMemPoolEntryHelper entry;
    LOCK2(cs_main, testPool.cs);
    // Create ProUpServ and test block reorg which double-spend ProRegTx
    auto tx_up_serv = CreateProUpServTx(setup.m_node, utxos, tx_reg.GetHash(), operatorKey, 2, setup.coinbaseKey);
    testPool.addUnchecked(entry.FromTx(tx_up_serv));
    // A disconnected block would insert ProRegTx back into mempool
    testPool.addUnchecked(entry.FromTx(tx_reg));
    BOOST_CHECK_EQUAL(testPool.size(), 2U);

    // Create a tx that will double-spend ProRegTx
    CMutableTransaction tx_reg_ds;
    tx_reg_ds.vin = tx_reg.vin;
    tx_reg_ds.vout.emplace_back(0, CScript() << OP_RETURN);
    SignTransaction(setup.m_node, tx_reg_ds, setup.coinbaseKey);

    // Check mempool as if a new block with tx_reg_ds was connected instead of the old one with tx_reg
    std::vector<CTransactionRef> block_reorg;
    block_reorg.emplace_back(std::make_shared<CTransaction>(tx_reg_ds));
    testPool.removeForBlock(block_reorg, nHeight + 2, setup.m_node.chainman->ActiveChain().Tip());
    BOOST_CHECK_EQUAL(testPool.size(), 0U);
}

void FuncTestMempoolDualProregtx(TestChain100Setup& setup)
{
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);

    // Create a MN
    CKey ownerKey1;
    CBLSSecretKey operatorKey1;
    auto tx_reg1 = CreateProRegTx(setup.m_node, utxos, 1, GenerateRandomAddress(), setup.coinbaseKey, ownerKey1, operatorKey1);

    // Create a MN with an external collateral that references tx_reg1
    CKey ownerKey;
    CKey payoutKey;
    CKey collateralKey;
    CBLSSecretKey operatorKey;

    ownerKey.MakeNewKey(true);
    payoutKey.MakeNewKey(true);
    collateralKey.MakeNewKey(true);
    operatorKey.MakeNewKey();

    auto scriptPayout = GetScriptForDestination(WitnessV0KeyHash(payoutKey.GetPubKey()));

    CProRegTx payload;
    payload.addr = LookupNumeric("1.1.1.1", 2);
    payload.keyIDOwner = ownerKey.GetPubKey().GetID();
    payload.pubKeyOperator.Set(operatorKey.GetPublicKey(), bls::bls_legacy_scheme.load());
    payload.keyIDVoting = ownerKey.GetPubKey().GetID();
    payload.scriptPayout = scriptPayout;

    for (size_t i = 0; i < tx_reg1.vout.size(); ++i) {
        if (tx_reg1.vout[i].nValue == 100 * COIN) {
            payload.collateralOutpoint = COutPoint(tx_reg1.GetHash(), i);
            break;
        }
    }

    CMutableTransaction tx_reg2;
    tx_reg2.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    FundTransaction(setup.m_node, tx_reg2, utxos, scriptPayout, 100 * COIN);
    payload.inputsHash = CalcTxInputsHash(CTransaction(tx_reg2));
    CMessageSigner::SignMessage(payload.MakeSignString(), payload.vchSig, collateralKey);
    SetTxPayload(tx_reg2, payload);
    SignTransaction(setup.m_node, tx_reg2, setup.coinbaseKey);

    CTxMemPool testPool{MemPoolOptionsForTest(setup.m_node)};
    TestMemPoolEntryHelper entry;
    LOCK2(cs_main, testPool.cs);

    testPool.addUnchecked(entry.FromTx(tx_reg1));
    BOOST_CHECK_EQUAL(testPool.size(), 1U);
    BOOST_CHECK(testPool.existsProviderTxConflict(CTransaction(tx_reg2), setup.m_node.chainman->ActiveChain().Tip()));
}

void FuncVerifyDB(TestChain100Setup& setup)
{
    int nHeight = *setup.m_node.chain->getHeight();
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);

    CKey ownerKey;
    CKey payoutKey;
    CKey collateralKey;
    CBLSSecretKey operatorKey;

    ownerKey.MakeNewKey(true);
    payoutKey.MakeNewKey(true);
    collateralKey.MakeNewKey(true);
    operatorKey.MakeNewKey();

    auto scriptPayout = GetScriptForDestination(WitnessV0KeyHash(payoutKey.GetPubKey()));
    auto scriptCollateral = GetScriptForDestination(WitnessV0KeyHash(collateralKey.GetPubKey()));

    // Create a MN with an external collateral
    CMutableTransaction tx_collateral;
    FundTransaction(setup.m_node, tx_collateral, utxos, scriptCollateral, 100 * COIN);
    SignTransaction(setup.m_node, tx_collateral, setup.coinbaseKey);


    auto block = setup.CreateAndProcessBlock({tx_collateral}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    assert(*setup.m_node.chain->getHeight() == nHeight + 1);
    assert(block.GetHash() == setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));

    CProRegTx payload;
    payload.addr = LookupNumeric("1.1.1.1", 1);
    payload.keyIDOwner = ownerKey.GetPubKey().GetID();
    payload.pubKeyOperator.Set(operatorKey.GetPublicKey(), bls::bls_legacy_scheme.load());
    payload.keyIDVoting = ownerKey.GetPubKey().GetID();
    payload.scriptPayout = scriptPayout;

    for (size_t i = 0; i < tx_collateral.vout.size(); ++i) {
        if (tx_collateral.vout[i].nValue == 100 * COIN) {
            payload.collateralOutpoint = COutPoint(tx_collateral.GetHash(), i);
            break;
        }
    }

    CMutableTransaction tx_reg;
    tx_reg.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    FundTransaction(setup.m_node, tx_reg, utxos, scriptPayout, 100 * COIN);
    payload.inputsHash = CalcTxInputsHash(CTransaction(tx_reg));
    CMessageSigner::SignMessage(payload.MakeSignString(), payload.vchSig, collateralKey);
    SetTxPayload(tx_reg, payload);
    SignTransaction(setup.m_node, tx_reg, setup.coinbaseKey);

    auto tx_reg_hash = tx_reg.GetHash();

    block = setup.CreateAndProcessBlock({tx_reg}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 2);
    BOOST_CHECK_EQUAL(block.GetHash() , setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));
    assert(deterministicMNManager->GetListAtChainTip().HasMN(tx_reg_hash));

    // Now spend the collateral while updating the same MN
    SimpleUTXOVec collateral_utxos;
    collateral_utxos.emplace_back(payload.collateralOutpoint, std::make_pair(1, 100 * COIN));
    auto proUpRevTx = CreateProUpRevTx(setup.m_node, collateral_utxos, tx_reg_hash, operatorKey, collateralKey);

    block = setup.CreateAndProcessBlock({proUpRevTx}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight() , nHeight + 3);
    BOOST_CHECK_EQUAL(block.GetHash() , setup.m_node.chain->getBlockHash(*setup.m_node.chain->getHeight()));
    assert(!deterministicMNManager->GetListAtChainTip().HasMN(tx_reg_hash));
    LOCK(cs_main);
    Chainstate& active_chainstate = setup.m_node.chainman->ActiveChainstate();
    // Verify db consistency
    assert(CVerifyDB(setup.m_node.chainman->GetNotifications()).VerifyDB(active_chainstate, Params().GetConsensus(), active_chainstate.CoinsTip(), 4, 2) == VerifyDBResult::SUCCESS);
}
BOOST_AUTO_TEST_SUITE(evo_dip3_activation_tests)

BOOST_AUTO_TEST_CASE(protx_bls_cache_binds_complete_authentication_tuple)
{
    using Result = CProTxBLSCache::Result;
    CBLSSecretKey key, other_key;
    key.MakeNewKey();
    other_key.MakeNewKey();
    const auto pubkey = key.GetPublicKey();
    const auto other_pubkey = other_key.GetPublicKey();
    const uint256 message = uint256::ONEV;
    const uint256 other_message = uint256::TWOV;

    for (const bool legacy : {false, true}) {
        const auto signature = key.Sign(message, legacy);
        const auto other_signature = other_key.Sign(message, legacy);
        BOOST_REQUIRE(signature.IsValid());
        BOOST_REQUIRE(other_signature.IsValid());
        CProTxBLSCache cache;
        BOOST_CHECK(cache.GetLastResult() == Result::UNVERIFIED);
        BOOST_REQUIRE(cache.Verify(signature, pubkey, message, legacy));
        BOOST_CHECK(cache.GetLastResult() == Result::VERIFIED);
        for (int i = 0; i < 10; ++i) {
            BOOST_REQUIRE(cache.Verify(signature, pubkey, message, legacy));
            BOOST_CHECK(cache.GetLastResult() == Result::CACHED);
        }
        BOOST_CHECK(!cache.Verify(CBLSSignature{}, pubkey, message, legacy));
        BOOST_CHECK(cache.GetLastResult() == Result::INVALID);
        BOOST_REQUIRE(cache.Verify(signature, pubkey, message, legacy));
        BOOST_CHECK(cache.GetLastResult() == Result::CACHED);
        BOOST_CHECK(!cache.Verify(signature, CBLSPublicKey{}, message, legacy));
        BOOST_CHECK(cache.GetLastResult() == Result::INVALID);
        BOOST_REQUIRE(cache.Verify(signature, pubkey, message, legacy));
        BOOST_CHECK(cache.GetLastResult() == Result::CACHED);

        auto reject_changed_tuple = [&](const CBLSSignature& changed_signature,
                                        const CBLSPublicKey& changed_pubkey,
                                        const uint256& changed_message, bool changed_legacy) {
            CProTxBLSCache changed_cache;
            BOOST_REQUIRE(changed_cache.Verify(signature, pubkey, message, legacy));
            BOOST_CHECK(!changed_cache.Verify(changed_signature, changed_pubkey, changed_message, changed_legacy));
            BOOST_CHECK(changed_cache.GetLastResult() == Result::INVALID);
            // Invalid proofs never become positive cache entries.
            BOOST_CHECK(!changed_cache.Verify(changed_signature, changed_pubkey, changed_message, changed_legacy));
            BOOST_CHECK(changed_cache.GetLastResult() == Result::INVALID);
            BOOST_REQUIRE(changed_cache.Verify(signature, pubkey, message, legacy));
            BOOST_CHECK(changed_cache.GetLastResult() == Result::CACHED);
        };
        reject_changed_tuple(signature, other_pubkey, message, legacy);
        reject_changed_tuple(signature, pubkey, other_message, legacy);
        reject_changed_tuple(other_signature, pubkey, message, legacy);
        reject_changed_tuple(signature, pubkey, message, !legacy);

        CProTxBLSCache unverified;
        BOOST_CHECK(!unverified.Verify(other_signature, pubkey, message, legacy));
        BOOST_CHECK(unverified.GetLastResult() == Result::INVALID);
        BOOST_REQUIRE(unverified.Verify(signature, pubkey, message, legacy));
        BOOST_CHECK(unverified.GetLastResult() == Result::VERIFIED);
        const auto new_signature = key.Sign(other_message, legacy);
        BOOST_REQUIRE(unverified.Verify(new_signature, pubkey, other_message, legacy));
        BOOST_CHECK(unverified.GetLastResult() == Result::VERIFIED);
        BOOST_REQUIRE(unverified.Verify(new_signature, pubkey, other_message, legacy));
        BOOST_CHECK(unverified.GetLastResult() == Result::CACHED);
    }
}

BOOST_AUTO_TEST_CASE(protx_bls_cache_reused_by_forward_cleanup)
{
    using Result = CProTxBLSCache::Result;
    TestChainDIP3V19Setup setup;
    auto& chainman = *setup.m_node.chainman;
    auto& pool = *setup.m_node.mempool;
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    const CScript payout = GetScriptForDestination(WitnessV0KeyHash(setup.coinbaseKey.GetPubKey()));
    const CScript coinbase_script = GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey());
    CKey owner_key;
    CBLSSecretKey operator_key;
    const auto registration = CreateProRegTx(setup.m_node, utxos, 1, payout,
        setup.coinbaseKey, owner_key, operator_key);
    setup.CreateAndProcessBlock({registration}, coinbase_script);
    const uint256 target = registration.GetHash();
    BOOST_REQUIRE(deterministicMNManager->GetListAtChainTip().HasMN(target));

    auto mine_fee_paying = [&](const CMutableTransaction& tx) {
        // The generic helper appends transactions after calculating a zero-fee
        // coinbase. Recalculate exact payments for this selected transaction.
        auto block_template = node::BlockAssembler{chainman.ActiveChainstate(), nullptr}.CreateNewBlock(coinbase_script);
        BOOST_REQUIRE(block_template != nullptr);
        CBlock block = block_template->block;
        {
            LOCK(cs_main);
            CAmount fee = -CTransaction(tx).GetValueOut();
            for (const auto& input : tx.vin) {
                const auto& coin = chainman.ActiveChainstate().CoinsTip().AccessCoin(input.prevout);
                BOOST_REQUIRE(!coin.IsSpent());
                fee += coin.out.nValue;
            }
            const int height = chainman.ActiveHeight() + 1;
            const CAmount reward = GetBlockSubsidy(height, chainman.GetConsensus());
            CMutableTransaction coinbase{*block.vtx.front()};
            const int witness_index = GetWitnessCommitmentIndex(block);
            BOOST_REQUIRE(witness_index >= 0);
            const CTxOut witness_commitment = coinbase.vout.at(witness_index);
            coinbase.vout.resize(1);
            coinbase.vout.front().nValue = reward + fee;
            std::vector<CTxOut> mn_payments, superblock_payments;
            FillBlockPayments(chainman.ActiveChain(), coinbase, height, reward, fee, mn_payments, superblock_payments);
            coinbase.vout.push_back(witness_commitment);
            block.vtx.front() = MakeTransactionRef(coinbase);
            block.vtx.push_back(MakeTransactionRef(tx));
            node::RegenerateCommitments(block, chainman, block_template->vchCoinbaseCommitmentExtra);
        }
        while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) ++block.nNonce;
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));
        return block;
    };
    auto make_service = [&](int port, const CBLSSecretKey& key) {
        auto tx = CreateProUpServTx(setup.m_node, utxos, target, key, port, setup.coinbaseKey);
        tx.vout.front().nValue -= 10000;
        SignTransaction(setup.m_node, tx, setup.coinbaseKey);
        return tx;
    };
    std::vector<CMutableTransaction> pending;
    for (int i = 0; i < 8; ++i) pending.push_back(make_service(100 + i, operator_key));
    pending.push_back(CreateProUpRevTx(setup.m_node, utxos, target, operator_key, setup.coinbaseKey));
    pending.back().vout.front().nValue -= 10000;
    SignTransaction(setup.m_node, pending.back(), setup.coinbaseKey);
    std::set<COutPoint> fee_inputs;
    for (const auto& tx : pending) {
        for (const auto& input : tx.vin) BOOST_REQUIRE(fee_inputs.insert(input.prevout).second);
    }

    {
        // Unchecked insertion and signature-skipping validation must not mint
        // evidence that the BLS signature was actually authenticated.
        CTxMemPool unchecked_pool{MemPoolOptionsForTest(setup.m_node)};
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, unchecked_pool.cs);
        unchecked_pool.addUnchecked(entry.FromTx(pending.front()));
        const auto it = unchecked_pool.GetIter(pending.front().GetHash());
        BOOST_REQUIRE(it.has_value());
        auto& cache = (*it)->GetProTxBLSCache();
        BOOST_CHECK(cache.GetLastResult() == Result::UNVERIFIED);
        TxValidationState state;
        BOOST_REQUIRE(CheckSpecialTx(chainman.m_blockman, CTransaction(pending.front()), chainman.ActiveTip(),
            state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true, /*check_sigs=*/false, &cache));
        BOOST_CHECK(cache.GetLastResult() == Result::UNVERIFIED);
    }

    {
        LOCK2(cs_main, pool.cs);
        for (const auto& tx : pending) {
            const auto result = chainman.ProcessTransaction(MakeTransactionRef(tx));
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                result.m_state.ToString());
            const auto it = pool.GetIter(tx.GetHash());
            BOOST_REQUIRE(it.has_value());
            BOOST_CHECK_EQUAL((*it)->GetCountWithAncestors(), 1U);
            BOOST_CHECK((*it)->GetProTxBLSCache().GetLastResult() == Result::VERIFIED);
        }
    }

    for (int port : {200, 201}) {
        const auto confirmed = make_service(port, operator_key);
        for (const auto& input : confirmed.vin) BOOST_REQUIRE(fee_inputs.insert(input.prevout).second);
        {
            LOCK(cs_main);
            const auto result = chainman.ProcessTransaction(MakeTransactionRef(confirmed));
            BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                result.m_state.ToString());
        }
        const auto block = mine_fee_paying(confirmed);
        BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()) == block.GetHash());
        const auto mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
        BOOST_REQUIRE(mn != nullptr);
        BOOST_CHECK_EQUAL(mn->pdmnState->addr.GetPort(), port);
        LOCK(pool.cs);
        BOOST_CHECK_EQUAL(pool.size(), pending.size());
        for (const auto& tx : pending) {
            const auto it = pool.GetIter(tx.GetHash());
            BOOST_REQUIRE(it.has_value());
            // VERIFIED would mean redundant pairing; UNVERIFIED would mean
            // admission or cleanup failed to propagate authentication evidence.
            BOOST_CHECK((*it)->GetProTxBLSCache().GetLastResult() == Result::CACHED);
        }
    }

    CProTxBLSCache old_authentication;
    {
        LOCK(pool.cs);
        const auto it = pool.GetIter(pending.front().GetHash());
        BOOST_REQUIRE(it.has_value());
        old_authentication = (*it)->GetProTxBLSCache();
    }
    CBLSSecretKey new_operator_key;
    new_operator_key.MakeNewKey();
    auto rotation = CreateProUpRegTx(setup.m_node, utxos, target, owner_key,
        new_operator_key.GetPublicKey(), owner_key.GetPubKey().GetID(), payout, setup.coinbaseKey);
    rotation.vout.front().nValue -= 10000;
    SignTransaction(setup.m_node, rotation, setup.coinbaseKey);
    const auto rotation_block = mine_fee_paying(rotation);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveTip()->GetBlockHash()) == rotation_block.GetHash());
    {
        LOCK2(cs_main, pool.cs);
        BOOST_CHECK_EQUAL(pool.size(), 0U);
        TxValidationState state;
        BOOST_CHECK(!CheckSpecialTx(chainman.m_blockman, CTransaction(pending.front()), chainman.ActiveTip(),
            state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true, /*check_sigs=*/true, &old_authentication));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-bls-sig");
        BOOST_CHECK(old_authentication.GetLastResult() == Result::INVALID);
    }
    const auto fresh = make_service(202, new_operator_key);
    CProTxBLSCache positive_bls_cache;
    {
        LOCK2(cs_main, pool.cs);
        const auto result = chainman.ProcessTransaction(MakeTransactionRef(fresh));
        BOOST_REQUIRE_MESSAGE(result.m_result_type == MempoolAcceptResult::ResultType::VALID,
            result.m_state.ToString());
        const auto it = pool.GetIter(fresh.GetHash());
        BOOST_REQUIRE(it.has_value());
        positive_bls_cache = (*it)->GetProTxBLSCache();
        BOOST_REQUIRE(positive_bls_cache.GetLastResult() == Result::VERIFIED);
    }

    // Registrar authorization belongs to the owner, regardless of any valid
    // operator-signature memo supplied by the caller.
    CKey wrong_owner;
    wrong_owner.MakeNewKey(true);
    const auto bad_registrar = CreateProUpRegTx(setup.m_node, utxos, target, wrong_owner,
        new_operator_key.GetPublicKey(), owner_key.GetPubKey().GetID(), payout, setup.coinbaseKey);
    {
        LOCK(cs_main);
        TxValidationState state;
        BOOST_CHECK(!CheckSpecialTx(chainman.m_blockman, CTransaction(bad_registrar), chainman.ActiveTip(),
            state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true, /*check_sigs=*/true,
            &positive_bls_cache));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-hash-sig");
        BOOST_CHECK(positive_bls_cache.GetLastResult() == Result::VERIFIED);
    }

    // Roll back the authorizing key while its service update and positive
    // proof are still pending. Adjacent-list assumptions cannot authenticate
    // this transaction against the restored old operator.
    CBlockIndex* rotation_index;
    {
        LOCK(cs_main);
        rotation_index = chainman.m_blockman.LookupBlockIndex(rotation_block.GetHash());
        BOOST_REQUIRE(rotation_index != nullptr);
    }
    BlockValidationState disconnect_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().InvalidateBlock(disconnect_state, rotation_index));
    BlockValidationState activate_state;
    BOOST_REQUIRE(chainman.ActiveChainstate().ActivateBestChain(activate_state));
    {
        LOCK2(cs_main, pool.cs);
        BOOST_CHECK(chainman.ActiveTip() == rotation_index->pprev);
        const auto restored = deterministicMNManager->GetListForBlock(chainman.ActiveTip()).GetMN(target);
        BOOST_REQUIRE(restored != nullptr);
        BOOST_CHECK(restored->pdmnState->pubKeyOperator.Get() == operator_key.GetPublicKey());
        BOOST_CHECK(!pool.exists(GenTxid::Txid(fresh.GetHash())));
        TxValidationState changed_key_state;
        BOOST_CHECK(!CheckSpecialTx(chainman.m_blockman, CTransaction(fresh), chainman.ActiveTip(),
            changed_key_state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true,
            /*check_sigs=*/true, &positive_bls_cache));
        BOOST_CHECK_EQUAL(changed_key_state.GetRejectReason(), "bad-protx-bls-sig");
        BOOST_CHECK(positive_bls_cache.GetLastResult() == Result::INVALID);
        TxValidationState restored_key_state;
        BOOST_REQUIRE(CheckSpecialTx(chainman.m_blockman, CTransaction(pending.front()), chainman.ActiveTip(),
            restored_key_state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true,
            /*check_sigs=*/true, &old_authentication));
        BOOST_CHECK(old_authentication.GetLastResult() == Result::CACHED);
    }
}

// DIP3 can only be activated with legacy scheme (v19 is activated later)
BOOST_AUTO_TEST_CASE(dip3_activation_legacy)
{
    TestChainDIP3BeforeActivationSetup setup;
    FuncDIP3Activation(setup);
}

BOOST_AUTO_TEST_CASE(dip3_protx_legacy)
{
    TestChainDIP3Setup setup;
    FuncDIP3Protx(setup);
}

BOOST_AUTO_TEST_CASE(dip3_protx_basic)
{
    TestChainDIP3V19Setup setup;
    FuncDIP3Protx(setup);
}

BOOST_AUTO_TEST_CASE(orphan_governance_vote_is_available_after_parent)
{
    TestChainDIP3V19Setup setup;
    BOOST_REQUIRE(governance != nullptr);
    BOOST_REQUIRE(governance->LoadCache(/*load_cache=*/false));

    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    CKey owner_key;
    CBLSSecretKey operator_key;
    const CMutableTransaction pro_reg = CreateProRegTx(
        setup.m_node, utxos, /*port=*/1,
        GetScriptForDestination(WitnessV0KeyHash(setup.coinbaseKey.GetPubKey())),
        setup.coinbaseKey, owner_key, operator_key);
    setup.CreateAndProcessBlock(
        {pro_reg}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    const auto mn_list = deterministicMNManager->GetListAtChainTip();
    const auto dmn = mn_list.GetMN(pro_reg.GetHash());
    BOOST_REQUIRE(dmn != nullptr);
    int last_superblock;
    int next_superblock;
    CSuperblock::GetNearestSuperblocksHeights(
        *setup.m_node.chain->getHeight(), last_superblock, next_superblock);
    BOOST_REQUIRE(CSuperblock::IsValidBlockHeight(next_superblock));

    std::vector<CGovernancePayment> payments;
    payments.emplace_back(PKHash(setup.coinbaseKey.GetPubKey()), COIN, uint256::ONEV);
    const CSuperblock schedule{next_superblock, std::move(payments)};
    CGovernanceObject trigger{
        uint256{}, /*revision=*/1, GetTime<std::chrono::seconds>().count(),
        uint256{}, schedule.GetHexStrData()};
    trigger.SetMasternodeOutpoint(dmn->collateralOutpoint);

    // Sign the wire object without changing this process's active masternode.
    Governance::Object signed_trigger = trigger.Object();
    signed_trigger.vchSig =
        operator_key.Sign(trigger.GetSignatureHash(), false).ToByteVector(false);
    CDataStream trigger_bytes{SER_NETWORK, PROTOCOL_VERSION};
    trigger_bytes << signed_trigger;
    trigger_bytes >> trigger;
    const uint256 trigger_hash = trigger.GetHash();
    BOOST_REQUIRE(trigger.CheckSignature(operator_key.GetPublicKey()));

    CGovernanceVote vote{
        dmn->collateralOutpoint, trigger_hash,
        VOTE_SIGNAL_FUNDING, VOTE_OUTCOME_YES};
    vote.SetSignature(
        operator_key.Sign(vote.GetSignatureHash(), false).ToByteVector(false));
    BOOST_REQUIRE(vote.IsValid(mn_list, /*useVotingKey=*/false));
    const uint256 vote_hash = vote.GetHash();

    // The vote arrives first. It must remain unavailable until its parent is
    // accepted, then become both locally counted and retrievable by a peer.
    CGovernanceException exception;
    BOOST_CHECK(!governance->ProcessVoteAndRelay(
        vote, mn_list, exception, *setup.m_node.connman, *setup.m_node.peerman));
    BOOST_CHECK_EQUAL(exception.GetType(), GOVERNANCE_EXCEPTION_WARNING);
    BOOST_CHECK(!governance->HaveObjectForHash(trigger_hash));
    BOOST_CHECK(!governance->HaveVoteForHash(vote_hash));
    CDataStream before_parent{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_CHECK(!governance->SerializeVoteForHash(vote_hash, before_parent));

    governance->AddGovernanceObject(trigger, *setup.m_node.peerman);
    BOOST_REQUIRE(governance->HaveObjectForHash(trigger_hash));
    const auto current_votes = governance->GetCurrentVotes(trigger_hash, COutPoint{});
    BOOST_REQUIRE_EQUAL(current_votes.size(), 1);
    BOOST_CHECK(current_votes.front().GetHash() == vote_hash);
    BOOST_CHECK(governance->HaveVoteForHash(vote_hash));

    CDataStream served_vote{SER_NETWORK, PROTOCOL_VERSION};
    BOOST_REQUIRE(governance->SerializeVoteForHash(vote_hash, served_vote));
    CDataStream expected_vote{SER_NETWORK, PROTOCOL_VERSION};
    expected_vote << vote;
    BOOST_CHECK_EQUAL_COLLECTIONS(
        served_vote.begin(), served_vote.end(),
        expected_vote.begin(), expected_vote.end());
    CGovernanceVote decoded_vote;
    served_vote >> decoded_vote;
    BOOST_CHECK(served_vote.empty());
    BOOST_CHECK(decoded_vote.GetHash() == vote_hash);
    BOOST_CHECK(decoded_vote.IsValid(mn_list, /*useVotingKey=*/false));
}

BOOST_AUTO_TEST_CASE(masternode_required_outputs_are_matched_once)
{
    TestChainDIP3V19Setup setup;
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    const CScript payout =
        GetScriptForDestination(WitnessV0KeyHash(setup.coinbaseKey.GetPubKey()));

    CKey owner_key;
    CBLSSecretKey operator_key;
    const CMutableTransaction pro_reg =
        CreateProRegTx(
            setup.m_node,
            utxos,
            /*port=*/1,
            payout,
            setup.coinbaseKey,
            owner_key,
            operator_key);
    setup.CreateAndProcessBlock(
        {pro_reg}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    const CMutableTransaction pro_up_serv =
        CreateProUpServTx(
            setup.m_node,
            utxos,
            pro_reg.GetHash(),
            operator_key,
            /*port=*/2,
            setup.coinbaseKey);
    setup.CreateAndProcessBlock(
        {pro_up_serv}, GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey()));

    CChain* active_chain = WITH_LOCK(
        ::cs_main, return &setup.m_node.chainman->ActiveChain());
    const int next_height = *setup.m_node.chain->getHeight() + 1;
    constexpr CAmount block_reward{100 * COIN};
    CAmount mn_seniority{0};
    CAmount mn_floor_diff{0};
    int collateral_height{0};
    std::vector<CTxOut> required_outputs;
    BOOST_REQUIRE(
        CMasternodePayments::GetBlockTxOuts(
            *active_chain,
            next_height,
            block_reward,
            required_outputs,
            /*nHalfFee=*/0,
            mn_seniority,
            mn_floor_diff,
            collateral_height));
    BOOST_REQUIRE_EQUAL(required_outputs.size(), 2);
    BOOST_REQUIRE(required_outputs[0] == required_outputs[1]);

    CMutableTransaction tx;
    tx.vout = {required_outputs[0]};
    mn_seniority = 0;
    mn_floor_diff = 0;
    BOOST_CHECK(
        !CMasternodePayments::IsTransactionValid(
            *active_chain,
            CTransaction{tx},
            next_height,
            block_reward,
            /*nHalfFee=*/0,
            mn_seniority,
            mn_floor_diff));

    tx.vout.push_back(required_outputs[1]);
    mn_seniority = 0;
    mn_floor_diff = 0;
    std::vector<bool> matched_outputs;
    BOOST_CHECK(
        CMasternodePayments::IsTransactionValid(
            *active_chain,
            CTransaction{tx},
            next_height,
            block_reward,
            /*nHalfFee=*/0,
            mn_seniority,
            mn_floor_diff,
            &matched_outputs));
    BOOST_REQUIRE_EQUAL(matched_outputs.size(), tx.vout.size());
    BOOST_CHECK(matched_outputs[0]);
    BOOST_CHECK(matched_outputs[1]);
}

BOOST_AUTO_TEST_CASE(test_mempool_reorg_legacy)
{
    TestChainDIP3Setup setup;
    FuncTestMempoolReorg(setup);
}

BOOST_AUTO_TEST_CASE(test_mempool_reorg_basic)
{
    TestChainDIP3V19Setup setup;
    FuncTestMempoolReorg(setup);
}

BOOST_AUTO_TEST_CASE(test_mempool_dual_proregtx_legacy)
{
    TestChainDIP3Setup setup;
    FuncTestMempoolDualProregtx(setup);
}

BOOST_AUTO_TEST_CASE(test_mempool_dual_proregtx_basic)
{
    TestChainDIP3V19Setup setup;
    FuncTestMempoolDualProregtx(setup);
}

enum class QuorumPoSeMempoolTest {
    BLOCK_CONTEXT,
    RESTORED_POOL,
    FORWARD_REVIVAL,
    FORWARD_RBF,
};

static void TestQuorumPoSeBanMempool(QuorumPoSeMempoolTest test)
{
    const bool forward_revival = test == QuorumPoSeMempoolTest::FORWARD_REVIVAL ||
        test == QuorumPoSeMempoolTest::FORWARD_RBF;
    const bool replace_inputs = test == QuorumPoSeMempoolTest::FORWARD_RBF;
    TestChainDIP3V19Setup setup;
    auto& chainman = *setup.m_node.chainman;
    auto& pool = *setup.m_node.mempool;
    auto utxos = BuildSimpleUTXOVec(setup.m_coinbase_txns);
    const CScript payout = GetScriptForDestination(WitnessV0KeyHash(setup.coinbaseKey.GetPubKey()));
    const CScript coinbase_script = GetScriptForRawPubKey(setup.coinbaseKey.GetPubKey());
    const auto& params = Params().GetConsensus().llmqTypeChainLocks;
    BOOST_REQUIRE_EQUAL(params.size, 3);
    BOOST_REQUIRE_EQUAL(params.minSize, 2);

    std::map<uint256, CBLSSecretKey> operator_keys;
    std::vector<CMutableTransaction> registrations;
    for (int i = 0; i < params.size; ++i) {
        CKey owner_key;
        CBLSSecretKey operator_key;
        auto registration = CreateProRegTx(setup.m_node, utxos, i + 1, payout,
            setup.coinbaseKey, owner_key, operator_key);
        operator_keys.emplace(registration.GetHash(), operator_key);
        registrations.push_back(std::move(registration));
    }
    const uint256 target = registrations.front().GetHash();
    setup.CreateAndProcessBlock(registrations, coinbase_script);
    BOOST_REQUIRE_EQUAL(deterministicMNManager->GetListAtChainTip().GetAllMNsCount(), 3U);

    // Two real commitments omit the same member. Each adds a 66% penalty;
    // one regtest DKG interval of decay between them still reaches the ban threshold.
    const int registration_height = *setup.m_node.chain->getHeight();
    const int first_base_height =
        (registration_height / params.dkgInterval + 1) * params.dkgInterval;
    const int first_commitment_height = first_base_height + params.dkgMiningWindowStart;
    setup.mineBlocks(first_commitment_height - 1 - registration_height);

    auto make_commitment = [&](int base_height) {
        LOCK(cs_main);
        const auto* base_index = chainman.ActiveChain()[base_height];
        BOOST_REQUIRE(base_index != nullptr);
        const auto members = llmq::CLLMQUtils::GetAllQuorumMembers(base_index);
        BOOST_REQUIRE_EQUAL(members.size(), 3U);

        llmq::CFinalCommitment commitment(base_index->GetBlockHash());
        const bool legacy = !llmq::CLLMQUtils::IsV19Active(base_height);
        commitment.nVersion = llmq::CFinalCommitment::GetVersion(!legacy);
        CBLSSecretKey quorum_key;
        quorum_key.MakeNewKey();
        commitment.quorumPublicKey = quorum_key.GetPublicKey();
        commitment.quorumVvecHash = GetRandHash();
        for (size_t i = 0; i < members.size(); ++i) {
            commitment.validMembers[i] = members[i]->proTxHash != target;
            commitment.signers[i] = commitment.validMembers[i];
        }
        BOOST_REQUIRE_EQUAL(commitment.CountValidMembers(), 2);
        const uint256 commitment_hash = llmq::BuildCommitmentHash(commitment.quorumHash,
            commitment.validMembers, commitment.quorumPublicKey, commitment.quorumVvecHash);
        commitment.quorumSig = quorum_key.Sign(commitment_hash, legacy);
        std::vector<CBLSSignature> signatures;
        std::vector<CBLSPublicKey> public_keys;
        for (size_t i = 0; i < members.size(); ++i) {
            if (!commitment.signers[i]) continue;
            const auto& key = operator_keys.at(members[i]->proTxHash);
            signatures.push_back(key.Sign(commitment_hash, legacy));
            public_keys.push_back(key.GetPublicKey());
        }
        commitment.membersSig = CBLSSignature::AggregateSecure(signatures, public_keys, commitment_hash);
        // Exercise the real membership and BLS checks before making it mineable.
        BOOST_REQUIRE(commitment.Verify(base_index, /*checkSigs=*/true));
        return commitment;
    };

    const auto first_commitment = make_commitment(first_base_height);
    llmq::quorumBlockProcessor->AddMineableCommitment(first_commitment);
    const CBlock first_block = setup.CreateAndProcessBlock({}, coinbase_script);
    BOOST_REQUIRE_EQUAL(*setup.m_node.chain->getHeight(), first_commitment_height);
    llmq::CFinalCommitmentTxPayload first_payload;
    BOOST_REQUIRE(GetTxPayload(*first_block.vtx.front(), first_payload));
    BOOST_CHECK(SerializeHash(first_payload.commitment) == SerializeHash(first_commitment));
    auto target_mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
    BOOST_REQUIRE(target_mn != nullptr);
    BOOST_CHECK_EQUAL(target_mn->pdmnState->nPoSePenalty, 66);
    BOOST_CHECK(!target_mn->pdmnState->IsBanned());

    const int second_base_height = first_base_height + params.dkgInterval;
    const int second_commitment_height = second_base_height + params.dkgMiningWindowStart;
    setup.mineBlocks(second_commitment_height - 1 - first_commitment_height);
    target_mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
    BOOST_REQUIRE(target_mn != nullptr);
    BOOST_REQUIRE(!target_mn->pdmnState->IsBanned());
    BOOST_REQUIRE(!target_mn->pdmnState->confirmedHash.IsNull());
    BOOST_REQUIRE(target_mn->pdmnState->nPoSePenalty - 1 + 66 >= 100);

    CMutableTransaction service_update = CreateProUpServTx(setup.m_node, utxos, target,
        operator_keys.at(target), /*port=*/forward_revival ? 1 : 10, setup.coinbaseKey);
    CProUpServTx service_payload;
    BOOST_REQUIRE(GetTxPayload(service_update, service_payload));
    service_payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
    service_payload.vchNEVMAddress.assign(20, 1);
    if (replace_inputs) {
        for (auto& input : service_update.vin) input.nSequence = CTxIn::SEQUENCE_FINAL - 2;
        service_payload.inputsHash = CalcTxInputsHash(CTransaction(service_update));
    }
    service_payload.sig = operator_keys.at(target).Sign(SerializeHash(service_payload), bls::bls_legacy_scheme);
    constexpr CAmount stale_fee{10000};
    service_update.vout.front().nValue -= stale_fee;
    SetTxPayload(service_update, service_payload);
    SignTransaction(setup.m_node, service_update, setup.coinbaseKey);
    CProUpServTx decoded_service_payload;
    BOOST_REQUIRE(GetTxPayload(service_update, decoded_service_payload));
    BOOST_REQUIRE(decoded_service_payload.vchNEVMAddress == service_payload.vchNEVMAddress);

    CMutableTransaction ordinary_tx;
    FundTransaction(setup.m_node, ordinary_tx, utxos, payout, COIN);
    ordinary_tx.vout.front().nValue -= 10000;
    SignTransaction(setup.m_node, ordinary_tx, setup.coinbaseKey);
    std::optional<CTxMemPoolEntry> original_service_entry;
    std::optional<CMutableTransaction> service_child;
    CProTxBLSCache service_authentication;
    {
        LOCK(cs_main);
        const auto service_result = chainman.ProcessTransaction(MakeTransactionRef(service_update));
        BOOST_REQUIRE_MESSAGE(service_result.m_result_type == MempoolAcceptResult::ResultType::VALID,
            service_result.m_state.ToString());
        BOOST_REQUIRE(service_result.m_base_fees.has_value());
        BOOST_CHECK_EQUAL(*service_result.m_base_fees, stale_fee);
        {
            LOCK(pool.cs);
            const auto entry = pool.GetIter(service_update.GetHash());
            BOOST_REQUIRE(entry.has_value());
            service_authentication = (*entry)->GetProTxBLSCache();
            BOOST_REQUIRE(service_authentication.GetLastResult() == CProTxBLSCache::Result::VERIFIED);
        }
        if (test == QuorumPoSeMempoolTest::RESTORED_POOL) {
            LOCK(pool.cs);
            const auto service_entry = pool.GetIter(service_update.GetHash());
            BOOST_REQUIRE(service_entry.has_value());
            BOOST_REQUIRE_EQUAL((*service_entry)->GetCountWithAncestors(), 1U);
            BOOST_REQUIRE_EQUAL((*service_entry)->GetCountWithDescendants(), 1U);
            original_service_entry.emplace(**service_entry);
        }
        if (forward_revival) {
            auto& child = service_child.emplace();
            child.vin.emplace_back(COutPoint(service_update.GetHash(), 0));
            child.vout.emplace_back(service_update.vout.front().nValue - 1000, payout);
            SignTransaction(setup.m_node, child, setup.coinbaseKey);
            const auto child_result = chainman.ProcessTransaction(MakeTransactionRef(child));
            BOOST_REQUIRE_MESSAGE(child_result.m_result_type == MempoolAcceptResult::ResultType::VALID,
                child_result.m_state.ToString());
            BOOST_REQUIRE(pool.exists(GenTxid::Txid(child.GetHash())));
        }
        const auto ordinary_result = chainman.ProcessTransaction(MakeTransactionRef(ordinary_tx));
        BOOST_REQUIRE_MESSAGE(ordinary_result.m_result_type == MempoolAcceptResult::ResultType::VALID,
            ordinary_result.m_state.ToString());
    }

    const auto second_commitment = make_commitment(second_base_height);
    BOOST_REQUIRE(llmq::quorumBlockProcessor->AddMineableCommitment(second_commitment).has_value());
    {
        LOCK(cs_main);
        BOOST_REQUIRE_EQUAL(chainman.ActiveHeight(), second_commitment_height - 1);
        llmq::CFinalCommitmentTxPayload mineable_payload;
        mineable_payload.nHeight = second_commitment_height;
        BOOST_REQUIRE(llmq::quorumBlockProcessor->GetMinableCommitment(second_commitment_height,
            mineable_payload.commitment));
        BOOST_REQUIRE(SerializeHash(mineable_payload.commitment) == SerializeHash(second_commitment));
        CBlock empty_block;
        empty_block.vtx.emplace_back();
        CDeterministicMNList next_list, old_list;
        BlockValidationState state;
        BOOST_REQUIRE_MESSAGE(deterministicMNManager->BuildNewListFromBlock(empty_block,
            chainman.ActiveTip(), state, chainman.ActiveChainstate().CoinsTip(), next_list, old_list,
            mineable_payload), state.ToString());
        const auto banned_mn = next_list.GetMN(target);
        BOOST_REQUIRE(banned_mn != nullptr);
        BOOST_REQUIRE_MESSAGE(banned_mn->pdmnState->IsBanned(),
            "candidate penalty: " << banned_mn->pdmnState->nPoSePenalty);
    }
    auto block_template = node::BlockAssembler{chainman.ActiveChainstate(), &pool}.CreateNewBlock(coinbase_script);
    BOOST_REQUIRE(block_template != nullptr);
    auto& block = block_template->block;
    llmq::CFinalCommitmentTxPayload second_payload;
    BOOST_REQUIRE(GetTxPayload(*block.vtx.front(), second_payload));
    BOOST_REQUIRE(SerializeHash(second_payload.commitment) == SerializeHash(second_commitment));
    BOOST_REQUIRE_EQUAL(block.vtx.size(), 2U);
    BOOST_CHECK(block.vtx[1]->GetHash() == ordinary_tx.GetHash());
    if (service_child) {
        BOOST_CHECK(std::none_of(block.vtx.begin(), block.vtx.end(), [&](const auto& tx) {
            return tx->GetHash() == service_child->GetHash();
        }));
    }
    {
        LOCK(cs_main);
        // The excluded update is valid at the parent, but fails after this exact
        // commitment is applied. Do not silently drop the commitment instead.
        CBlock invalid_block = block;
        invalid_block.vtx.push_back(MakeTransactionRef(service_update));
        CDeterministicMNList invalid_list, old_list;
        BlockValidationState state;
        BOOST_CHECK(!deterministicMNManager->BuildNewListFromBlock(invalid_block, chainman.ActiveTip(),
            state, chainman.ActiveChainstate().CoinsTip(), invalid_list, old_list, second_payload));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-banned-nevm-address");
    }

    node::RegenerateCommitments(block, chainman, block_template->vchCoinbaseCommitmentExtra);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainman.GetConsensus())) ++block.nNonce;
    BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(block), true, true, nullptr));
    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight(), second_commitment_height);
    target_mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
    BOOST_REQUIRE(target_mn != nullptr);
    BOOST_CHECK(target_mn->pdmnState->IsBanned());
    BOOST_CHECK(target_mn->pdmnState->vchNEVMAddress.empty());
    {
        LOCK(cs_main);
        TxValidationState cached_state;
        BOOST_CHECK(!CheckSpecialTx(chainman.m_blockman, CTransaction(service_update), chainman.ActiveTip(),
            cached_state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/true, /*check_sigs=*/true,
            &service_authentication));
        BOOST_CHECK_EQUAL(cached_state.GetRejectReason(), "bad-protx-banned-nevm-address");
    }

    const bool stale_evicted = !pool.exists(GenTxid::Txid(service_update.GetHash()));
    const bool stale_child_evicted = !service_child || !pool.exists(GenTxid::Txid(service_child->GetHash()));
    if (forward_revival) {
        BOOST_REQUIRE(!deterministicMNManager->GetListAtChainTip().HasUniqueProperty(service_payload.vchNEVMAddress));

        // Keep the registered endpoint. A stale provider reservation must not
        // block either a fresh-input revival or an explicit 11x-fee replacement.
        CMutableTransaction revival = replace_inputs ? service_update : CreateProUpServTx(setup.m_node, utxos,
            target, operator_keys.at(target), /*port=*/1, setup.coinbaseKey);
        CProUpServTx revival_payload;
        BOOST_REQUIRE(GetTxPayload(revival, revival_payload));
        revival_payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
        revival_payload.vchNEVMAddress.clear();
        revival_payload.sig = operator_keys.at(target).Sign(SerializeHash(revival_payload), bls::bls_legacy_scheme);
        const CAmount revival_fee = (replace_inputs ? 11 : 2) * stale_fee;
        revival.vout.front().nValue -= revival_fee - (replace_inputs ? stale_fee : 0);
        SetTxPayload(revival, revival_payload);
        SignTransaction(setup.m_node, revival, setup.coinbaseKey);
        if (replace_inputs) {
            BOOST_REQUIRE_EQUAL(revival.vin.size(), service_update.vin.size());
            for (size_t i = 0; i < revival.vin.size(); ++i) {
                BOOST_REQUIRE(revival.vin[i].prevout == service_update.vin[i].prevout);
            }
        } else {
            for (const auto& input : revival.vin) {
                for (const auto& stale_input : service_update.vin) {
                    BOOST_REQUIRE(input.prevout != stale_input.prevout);
                }
            }
        }

        const uint256 other_target = registrations[1].GetHash();
        CMutableTransaction reuse = CreateProUpServTx(setup.m_node, utxos, other_target,
            operator_keys.at(other_target), /*port=*/2, setup.coinbaseKey);
        CProUpServTx reuse_payload;
        BOOST_REQUIRE(GetTxPayload(reuse, reuse_payload));
        reuse_payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
        reuse_payload.vchNEVMAddress = service_payload.vchNEVMAddress;
        reuse_payload.sig = operator_keys.at(other_target).Sign(SerializeHash(reuse_payload), bls::bls_legacy_scheme);
        constexpr CAmount reuse_fee{15000};
        reuse.vout.front().nValue -= reuse_fee;
        SetTxPayload(reuse, reuse_payload);
        SignTransaction(setup.m_node, reuse, setup.coinbaseKey);
        for (const auto& input : reuse.vin) {
            for (const auto& stale_input : service_update.vin) BOOST_REQUIRE(input.prevout != stale_input.prevout);
            for (const auto& revival_input : revival.vin) BOOST_REQUIRE(input.prevout != revival_input.prevout);
        }

        bool revival_accepted{false}, reuse_accepted{false};
        {
            LOCK(cs_main);
            TxValidationState revival_state, reuse_state;
            BOOST_REQUIRE(CheckSpecialTx(chainman.m_blockman, CTransaction(revival), chainman.ActiveTip(),
                revival_state, chainman.ActiveChainstate().CoinsTip(), false, true));
            BOOST_REQUIRE(CheckSpecialTx(chainman.m_blockman, CTransaction(reuse), chainman.ActiveTip(),
                reuse_state, chainman.ActiveChainstate().CoinsTip(), false, true));
            const auto revival_result = chainman.ProcessTransaction(MakeTransactionRef(revival));
            revival_accepted = revival_result.m_result_type == MempoolAcceptResult::ResultType::VALID;
            BOOST_CHECK_MESSAGE(revival_accepted, "same-endpoint revival: " << revival_result.m_state.ToString());
            if (revival_accepted) {
                BOOST_REQUIRE(revival_result.m_base_fees.has_value());
                BOOST_CHECK_EQUAL(*revival_result.m_base_fees, revival_fee);
            }
            const auto reuse_result = chainman.ProcessTransaction(MakeTransactionRef(reuse));
            reuse_accepted = reuse_result.m_result_type == MempoolAcceptResult::ResultType::VALID;
            BOOST_CHECK_MESSAGE(reuse_accepted, "unowned NEVM address reuse: " << reuse_result.m_state.ToString());
            if (reuse_accepted) {
                BOOST_REQUIRE(reuse_result.m_base_fees.has_value());
                BOOST_CHECK_EQUAL(*reuse_result.m_base_fees, reuse_fee);
            }
        }
        BOOST_CHECK_MESSAGE(stale_child_evicted, "connected quorum PoSe ban retained an invalid provider's descendant");
        BOOST_REQUIRE_MESSAGE(stale_evicted, "connected quorum PoSe ban retained an invalid provider reservation");
        BOOST_REQUIRE(stale_child_evicted);
        BOOST_REQUIRE(revival_accepted && reuse_accepted);

        auto recovered_template = node::BlockAssembler{chainman.ActiveChainstate(), &pool}.CreateNewBlock(coinbase_script);
        BOOST_REQUIRE(recovered_template != nullptr);
        auto& recovered_block = recovered_template->block;
        BOOST_REQUIRE_EQUAL(recovered_block.vtx.size(), 3U);
        std::set<uint256> selected;
        for (size_t i = 1; i < recovered_block.vtx.size(); ++i) selected.insert(recovered_block.vtx[i]->GetHash());
        BOOST_CHECK_EQUAL(selected.count(revival.GetHash()), 1U);
        BOOST_CHECK_EQUAL(selected.count(reuse.GetHash()), 1U);
        node::RegenerateCommitments(recovered_block, chainman, recovered_template->vchCoinbaseCommitmentExtra);
        while (!CheckProofOfWork(recovered_block.GetHash(), recovered_block.nBits, chainman.GetConsensus())) ++recovered_block.nNonce;
        BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(recovered_block), true, true, nullptr));
        BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight(), second_commitment_height + 1);
        const auto recovered_list = deterministicMNManager->GetListAtChainTip();
        target_mn = recovered_list.GetMN(target);
        const auto other_mn = recovered_list.GetMN(other_target);
        BOOST_REQUIRE(target_mn != nullptr && other_mn != nullptr);
        BOOST_CHECK(!target_mn->pdmnState->IsBanned());
        BOOST_CHECK_EQUAL(target_mn->pdmnState->addr.GetPort(), 1);
        BOOST_CHECK(target_mn->pdmnState->vchNEVMAddress.empty());
        BOOST_CHECK(!other_mn->pdmnState->IsBanned());
        BOOST_CHECK_EQUAL(other_mn->pdmnState->addr.GetPort(), 2);
        BOOST_CHECK(other_mn->pdmnState->vchNEVMAddress == service_payload.vchNEVMAddress);
        BOOST_CHECK(!pool.exists(GenTxid::Txid(service_update.GetHash())));
        return;
    }

    BOOST_REQUIRE_MESSAGE(stale_evicted, "connected quorum PoSe ban retained an invalid provider transaction");
    if (test == QuorumPoSeMempoolTest::BLOCK_CONTEXT) return;

    // Restore only the exact signed entry admitted before the ban. This models
    // stale restored-pool defense, not successful admission against a banned MN.
    BOOST_REQUIRE(original_service_entry.has_value());
    {
        LOCK2(cs_main, pool.cs);
        pool.addUnchecked(*original_service_entry);
    }
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(service_update.GetHash())));
    {
        LOCK(cs_main);
        TxValidationState stale_state;
        BOOST_CHECK(!CheckSpecialTx(chainman.m_blockman, CTransaction(service_update), chainman.ActiveTip(),
            stale_state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/false, /*check_sigs=*/true));
        BOOST_CHECK_EQUAL(stale_state.GetRejectReason(), "bad-protx-banned-nevm-address");
    }

    CMutableTransaction revival = CreateProUpServTx(setup.m_node, utxos, target,
        operator_keys.at(target), /*port=*/11, setup.coinbaseKey);
    CProUpServTx revival_payload;
    BOOST_REQUIRE(GetTxPayload(revival, revival_payload));
    revival_payload.nVersion = CProUpServTx::UPDATE_NEVM_VERSION;
    BOOST_REQUIRE(revival_payload.vchNEVMAddress.empty());
    revival_payload.sig = operator_keys.at(target).Sign(SerializeHash(revival_payload), bls::bls_legacy_scheme);
    constexpr CAmount revival_fee{2 * stale_fee};
    revival.vout.front().nValue -= revival_fee;
    SetTxPayload(revival, revival_payload);
    SignTransaction(setup.m_node, revival, setup.coinbaseKey);
    for (const auto& stale_input : service_update.vin) {
        for (const auto& revival_input : revival.vin) {
            BOOST_REQUIRE(stale_input.prevout != revival_input.prevout);
        }
    }
    BOOST_REQUIRE(revival_fee * GetVirtualTransactionSize(CTransaction(service_update)) >
        stale_fee * GetVirtualTransactionSize(CTransaction(revival)));
    {
        LOCK(cs_main);
        const auto revival_result = chainman.ProcessTransaction(MakeTransactionRef(revival));
        BOOST_REQUIRE_MESSAGE(revival_result.m_result_type == MempoolAcceptResult::ResultType::VALID,
            revival_result.m_state.ToString());
        BOOST_REQUIRE(revival_result.m_base_fees.has_value());
        BOOST_CHECK_EQUAL(*revival_result.m_base_fees, revival_fee);
    }
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(service_update.GetHash())));
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(revival.GetHash())));

    // The higher actual feerate chooses the empty-NEVM revival first. Ordered
    // candidate state alone would then accept the stale update and fail the
    // consensus check, which validates each payload against the parent list.
    auto revived_template = node::BlockAssembler{chainman.ActiveChainstate(), &pool}.CreateNewBlock(coinbase_script);
    BOOST_REQUIRE(revived_template != nullptr);
    auto& revived_block = revived_template->block;
    BOOST_REQUIRE_EQUAL(revived_block.vtx.size(), 2U);
    BOOST_CHECK(revived_block.vtx[1]->GetHash() == revival.GetHash());
    node::RegenerateCommitments(revived_block, chainman, revived_template->vchCoinbaseCommitmentExtra);
    while (!CheckProofOfWork(revived_block.GetHash(), revived_block.nBits, chainman.GetConsensus())) ++revived_block.nNonce;
    BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(revived_block), true, true, nullptr));
    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight(), second_commitment_height + 1);
    target_mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
    BOOST_REQUIRE(target_mn != nullptr);
    BOOST_CHECK(!target_mn->pdmnState->IsBanned());
    BOOST_CHECK_EQUAL(target_mn->pdmnState->addr.GetPort(), 11);
    BOOST_CHECK(target_mn->pdmnState->vchNEVMAddress.empty());

    // Once the revival is confirmed, the unchanged pending update is valid
    // against the new parent and must be mineable without re-submission.
    BOOST_REQUIRE(pool.exists(GenTxid::Txid(service_update.GetHash())));
    {
        LOCK(cs_main);
        TxValidationState pending_state;
        BOOST_REQUIRE_MESSAGE(CheckSpecialTx(chainman.m_blockman, CTransaction(service_update), chainman.ActiveTip(),
            pending_state, chainman.ActiveChainstate().CoinsTip(), /*fJustCheck=*/false, /*check_sigs=*/true),
            pending_state.ToString());
    }
    auto pending_template = node::BlockAssembler{chainman.ActiveChainstate(), &pool}.CreateNewBlock(coinbase_script);
    BOOST_REQUIRE(pending_template != nullptr);
    auto& pending_block = pending_template->block;
    BOOST_REQUIRE_EQUAL(pending_block.vtx.size(), 2U);
    BOOST_CHECK(pending_block.vtx[1]->GetHash() == service_update.GetHash());
    node::RegenerateCommitments(pending_block, chainman, pending_template->vchCoinbaseCommitmentExtra);
    while (!CheckProofOfWork(pending_block.GetHash(), pending_block.nBits, chainman.GetConsensus())) ++pending_block.nNonce;
    BOOST_REQUIRE(chainman.ProcessNewBlock(std::make_shared<const CBlock>(pending_block), true, true, nullptr));
    BOOST_CHECK_EQUAL(*setup.m_node.chain->getHeight(), second_commitment_height + 2);
    target_mn = deterministicMNManager->GetListAtChainTip().GetMN(target);
    BOOST_REQUIRE(target_mn != nullptr);
    BOOST_CHECK(!target_mn->pdmnState->IsBanned());
    BOOST_CHECK_EQUAL(target_mn->pdmnState->addr.GetPort(), 10);
    BOOST_CHECK(target_mn->pdmnState->vchNEVMAddress == service_payload.vchNEVMAddress);
}

BOOST_AUTO_TEST_CASE(quorum_pose_ban_filters_nevm_update_from_block_template)
{
    TestQuorumPoSeBanMempool(QuorumPoSeMempoolTest::BLOCK_CONTEXT);
}

BOOST_AUTO_TEST_CASE(quorum_pose_ban_restored_update_does_not_reenter_via_revival)
{
    TestQuorumPoSeBanMempool(QuorumPoSeMempoolTest::RESTORED_POOL);
}

BOOST_AUTO_TEST_CASE(quorum_pose_ban_clears_provider_reservations)
{
    TestQuorumPoSeBanMempool(QuorumPoSeMempoolTest::FORWARD_REVIVAL);
}

BOOST_AUTO_TEST_CASE(quorum_pose_ban_clears_provider_reservations_for_rbf)
{
    TestQuorumPoSeBanMempool(QuorumPoSeMempoolTest::FORWARD_RBF);
}

//This one can be started only with legacy scheme, since inside undo block will switch it back to legacy resulting into an inconsistency
BOOST_AUTO_TEST_CASE(verify_db_legacy)
{
    TestChainDIP3Setup setup;
    FuncVerifyDB(setup);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(evo_dmn_db_maintenance_tests)

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

    auto db_params = DBParams{
        .path = "testdb_dmn_incremental_append_prune",
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

BOOST_AUTO_TEST_SUITE_END()
