// Copyright (c) 2013-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <hash.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <test/data/sighash.json.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <version.h>

#include <iostream>

#include <boost/test/unit_test.hpp>

#include <univalue.h>

// Old script.cpp SignatureHash function
uint256 static SignatureHashOld(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    if (nIn >= txTo.vin.size())
    {
        return uint256::ONEV;
    }
    CMutableTransaction txTmp(txTo);

    // In case concatenating two scripts ends up with two codeseparators,
    // or an extra one at the end, this prevents all those possible incompatibilities.
    FindAndDelete(scriptCode, CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for (unsigned int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCode;

    // Blank out some of the outputs
    if ((nHashType & 0x1f) == SIGHASH_NONE)
    {
        // Wildcard payee
        txTmp.vout.clear();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }
    else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
    {
        // Only lock-in the txout payee at same index as txin
        unsigned int nOut = nIn;
        if (nOut >= txTmp.vout.size())
        {
            return uint256::ONEV;
        }
        txTmp.vout.resize(nOut+1);
        for (unsigned int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();

        // Let the others update at will
        for (unsigned int i = 0; i < txTmp.vin.size(); i++)
            if (i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely, not recommended for open transactions
    if (nHashType & SIGHASH_ANYONECANPAY)
    {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize and hash
    CHashWriter ss{SERIALIZE_TRANSACTION_NO_WITNESS};
    ss << txTmp << nHashType;
    return ss.GetHash();
}

void static RandomScript(CScript &script) {
    static const opcodetype oplist[] = {OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR};
    script = CScript();
    int ops = (InsecureRandRange(10));
    for (int i=0; i<ops; i++)
        script << oplist[InsecureRandRange(std::size(oplist))];
}

void static RandomTransaction(CMutableTransaction& tx, bool fSingle)
{
    tx.nVersion = int(InsecureRand32());
    tx.vin.clear();
    tx.vout.clear();
    tx.nLockTime = (InsecureRandBool()) ? InsecureRand32() : 0;
    int ins = (InsecureRandBits(2)) + 1;
    int outs = fSingle ? ins : (InsecureRandBits(2)) + 1;
    for (int in = 0; in < ins; in++) {
        tx.vin.emplace_back();
        CTxIn &txin = tx.vin.back();
        txin.prevout.hash = InsecureRand256();
        txin.prevout.n = InsecureRandBits(2);
        RandomScript(txin.scriptSig);
        txin.nSequence = (InsecureRandBool()) ? InsecureRand32() : std::numeric_limits<uint32_t>::max();
    }
    for (int out = 0; out < outs; out++) {
        tx.vout.emplace_back();
        CTxOut &txout = tx.vout.back();
        txout.nValue = InsecureRandMoneyAmount();
        RandomScript(txout.scriptPubKey);
    }
}

BOOST_FIXTURE_TEST_SUITE(sighash_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sighash_test)
{
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "[\n";
    std::cout << "\t[\"raw_transaction, script, input_index, hashType, signature_hash (result)\"],\n";
    int nRandomTests = 500;
    #else
    int nRandomTests = 50000;
    #endif
    for (int i=0; i<nRandomTests; i++) {
        int nHashType{int(InsecureRand32())};
        CMutableTransaction txTo;
        RandomTransaction(txTo, (nHashType & 0x1f) == SIGHASH_SINGLE);
        CScript scriptCode;
        RandomScript(scriptCode);
        int nIn = InsecureRandRange(txTo.vin.size());

        uint256 sh, sho;
        sho = SignatureHashOld(scriptCode, CTransaction(txTo), nIn, nHashType);
        sh = SignatureHash(scriptCode, txTo, nIn, nHashType, 0, SigVersion::BASE);
        #if defined(PRINT_SIGHASH_JSON)
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << txTo;

        std::cout << "\t[\"" ;
        std::cout << HexStr(ss) << "\", \"";
        std::cout << HexStr(scriptCode) << "\", ";
        std::cout << nIn << ", ";
        std::cout << nHashType << ", \"";
        std::cout << sho.GetHex() << "\"]";
        if (i+1 != nRandomTests) {
          std::cout << ",";
        }
        std::cout << "\n";
        #endif
        BOOST_CHECK(sh == sho);
    }
    #if defined(PRINT_SIGHASH_JSON)
    std::cout << "]\n";
    #endif
}

// Goal: check that SignatureHash generates correct hash
// SYSCOIN
/*BOOST_AUTO_TEST_CASE(sighash_from_data)
{
    UniValue tests = read_json(json_tests::sighash);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        if (test.size() == 1) continue; // comment

        std::string raw_tx, raw_script, sigHashHex;
        int nIn, nHashType;
        uint256 sh;
        CTransactionRef tx;
        CScript scriptCode = CScript();

        try {
          // deserialize test data
          raw_tx = test[0].get_str();
          raw_script = test[1].get_str();
          nIn = test[2].getInt<int>();
          nHashType = test[3].getInt<int>();
          sigHashHex = test[4].get_str();

          CDataStream stream(ParseHex(raw_tx), SER_NETWORK, PROTOCOL_VERSION);
          stream >> tx;

          TxValidationState state;
          BOOST_CHECK_MESSAGE(CheckTransaction(*tx, state), strTest);
          BOOST_CHECK(state.IsValid());

          std::vector<unsigned char> raw = ParseHex(raw_script);
          scriptCode.insert(scriptCode.end(), raw.begin(), raw.end());
        } catch (...) {
          BOOST_ERROR("Bad test, couldn't deserialize data: " << strTest);
          continue;
        }

        sh = SignatureHash(scriptCode, *tx, nIn, nHashType, 0, SigVersion::BASE);
        BOOST_CHECK_MESSAGE(sh.GetHex() == sigHashHex, strTest);
    }
}*/

BOOST_AUTO_TEST_CASE(sighash_caching)
{
    for (int iteration = 0; iteration < 32; ++iteration) {
        CMutableTransaction tx;
        RandomTransaction(tx, false);
        // Always exercise both in-range and out-of-range SIGHASH_SINGLE.
        tx.vin.resize(3);
        tx.vout.resize(2);
        CScript script;
        RandomScript(script);
        const CScript other_script{CScript{script} << OP_CODESEPARATOR << OP_1};
        const CAmount amount{InsecureRandMoneyAmount()};
        std::vector<int> hash_types{0, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE,
            SIGHASH_ANYONECANPAY, SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            std::numeric_limits<int>::max(), std::numeric_limits<int>::min()};
        for (int i = 0; i < 256; ++i) hash_types.push_back(i);
        for (int i = 0; i < 16; ++i) hash_types.push_back(int(InsecureRand32()));

        for (const unsigned int input : {0U, 2U}) {
            SigHashCache cache;
            for (const int hash_type : hash_types) {
                // Share the cache across signature versions as well as scriptCodes.
                for (const auto sigversion : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
                    const bool expect_one{sigversion == SigVersion::BASE &&
                        (hash_type & 0x1f) == SIGHASH_SINGLE && input >= tx.vout.size()};
                    for (const auto& script_code : {script, other_script, script}) {
                        const auto expected{SignatureHash(script_code, tx, input, hash_type, amount, sigversion)};
                        BOOST_CHECK_EQUAL(SignatureHash(script_code, tx, input, hash_type, amount, sigversion, nullptr, &cache), expected);
                        // A second calculation must use the stored midstate without changing its result.
                        BOOST_CHECK_EQUAL(SignatureHash(script_code, tx, input, hash_type, amount, sigversion, nullptr, &cache), expected);
                        if (sigversion == SigVersion::BASE) {
                            BOOST_CHECK_EQUAL(expected, SignatureHashOld(script_code, CTransaction{tx}, input, hash_type));
                        }
                        if (expect_one) BOOST_CHECK_EQUAL(expected, uint256::ONEV);
                    }
                }
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(sighash_cache_midstate_reuse)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.emplace_back(1, CScript{} << OP_TRUE);
    const CScript script{CScript{} << OP_TRUE};
    const CScript other_script{CScript{} << OP_FALSE};
    for (const auto sigversion : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        SigHashCache cache;
        // Distinct hash types in the same serialization class share the midstate,
        // but append the complete hash-type word (including undefined bits).
        HashWriter stored{};
        stored << 42;
        cache.Store(SIGHASH_ALL, script, sigversion, stored);
        for (const int hash_type : {int{SIGHASH_ALL}, 0, 0x41, 0x101}) {
            const auto loaded{cache.Load(hash_type, script, sigversion)};
            BOOST_REQUIRE(loaded.has_value());
            auto expected{stored};
            expected << hash_type;
            BOOST_CHECK_EQUAL(SignatureHash(script, tx, 0, hash_type, 1, sigversion, nullptr, &cache), expected.GetHash());
        }
        // Different serialization classes, scriptCodes, and signature versions cannot hit.
        BOOST_CHECK(!cache.Load(SIGHASH_NONE, script, sigversion));
        BOOST_CHECK(!cache.Load(SIGHASH_SINGLE, script, sigversion));
        BOOST_CHECK(!cache.Load(SIGHASH_ALL | SIGHASH_ANYONECANPAY, script, sigversion));
        BOOST_CHECK(!cache.Load(SIGHASH_ALL, other_script, sigversion));
        BOOST_CHECK(!cache.Load(SIGHASH_ALL, script,
            sigversion == SigVersion::BASE ? SigVersion::WITNESS_V0 : SigVersion::BASE));

        // Populating one of the six slots does not evict a different class.
        cache.Store(SIGHASH_NONE, other_script, sigversion, HashWriter{});
        BOOST_CHECK(cache.Load(SIGHASH_ALL, script, sigversion).has_value());
        cache.Store(SIGHASH_ALL, other_script, sigversion, HashWriter{});
        BOOST_CHECK(!cache.Load(SIGHASH_ALL, script, sigversion));
        BOOST_CHECK(cache.Load(SIGHASH_ALL, other_script, sigversion).has_value());
    }

    // The historical legacy SINGLE bug bypasses even a populated cache entry.
    tx.vout.clear();
    SigHashCache cache;
    cache.Store(SIGHASH_SINGLE, script, SigVersion::BASE, HashWriter{});
    BOOST_CHECK_EQUAL(SignatureHash(script, tx, 0, SIGHASH_SINGLE, 1, SigVersion::BASE, nullptr, &cache), uint256::ONEV);
}


BOOST_AUTO_TEST_CASE(sighash_cache_script_execution)
{
    class RecordingSignatureChecker : public TransactionSignatureChecker {
    public:
        mutable std::vector<uint256> hashes;
        using TransactionSignatureChecker::TransactionSignatureChecker;
        bool VerifyECDSASignature(const std::vector<unsigned char>&, const CPubKey&, const uint256& hash) const override
        {
            hashes.push_back(hash);
            return true;
        }
    };

    CKey key;
    key.MakeNewKey(true);
    const auto pubkey{ToByteVector(key.GetPubKey())};
    const std::vector<unsigned char> signature{SIGHASH_ALL};
    const CScript suffix{CScript{} << signature << pubkey << OP_CHECKSIG};
    // The first two checks share a scriptCode. CODESEPARATOR changes the third.
    const CScript script{CScript{} << signature << pubkey << OP_CHECKSIGVERIFY
        << signature << pubkey << OP_CHECKSIGVERIFY << OP_CODESEPARATOR};
    CScript full_script{script};
    full_script.insert(full_script.end(), suffix.begin(), suffix.end());
    CScript legacy_script{full_script};
    CScript legacy_suffix{suffix};
    FindAndDelete(legacy_script, CScript{} << signature);
    FindAndDelete(legacy_suffix, CScript{} << signature);

    CMutableTransaction mutable_tx;
    RandomTransaction(mutable_tx, true);
    const CTransaction tx{mutable_tx};
    for (unsigned int input = 0; input < tx.vin.size(); ++input) {
        const CAmount amount{input + 1};
        RecordingSignatureChecker checker{&tx, input, amount, MissingDataBehavior::ASSERT_FAIL};
        for (const auto version : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
            checker.hashes.clear();
            std::vector<std::vector<unsigned char>> stack;
            BOOST_REQUIRE(EvalScript(stack, full_script, SCRIPT_VERIFY_NONE, checker, version));
            BOOST_REQUIRE_EQUAL(checker.hashes.size(), 3U);
            const auto& first_code{version == SigVersion::BASE ? legacy_script : full_script};
            const auto& last_code{version == SigVersion::BASE ? legacy_suffix : suffix};
            const auto expected_first{SignatureHash(first_code, tx, input, SIGHASH_ALL, amount, version)};
            const auto expected_last{SignatureHash(last_code, tx, input, SIGHASH_ALL, amount, version)};
            BOOST_CHECK_EQUAL(checker.hashes[0], expected_first);
            BOOST_CHECK_EQUAL(checker.hashes[1], expected_first);
            BOOST_CHECK_EQUAL(checker.hashes[2], expected_last);
            BOOST_CHECK(expected_first != expected_last);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
