#include <boost/test/unit_test.hpp>
#include <test/data/nevmspv_valid.json.h>
#include <test/data/nevmspv_invalid.json.h>

#include <uint256.h>
#include <util/strencodings.h>
#include <nevm/nevm.h>
#include <nevm/common.h>
#include <nevm/rlp.h>
#include <nevm/address.h>
#include <nevm/sha3.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <policy/policy.h>
#include <univalue.h>
#include <key_io.h>
#include <test/util/setup_common.h>
#include <test/util/json.h>
#include <validation.h>
#include <consensus/validation.h>
#include <services/assetconsensus.h>
BOOST_FIXTURE_TEST_SUITE(nevm_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(seniority_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensusParams = chainParams->GetConsensus();
    const int oldSr1Height = 525600;
    const int oldSr2Height = oldSr1Height*2.5;
    const int newSr1Height = oldSr1Height/2.5;
    const int newSr2Height = newSr1Height*2.5;
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock, 0), consensusParams.nSeniorityLevel2);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock+1, 0), consensusParams.nSeniorityLevel2);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock, consensusParams.nNEVMStartBlock), 0);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(1000000, 1000000), 0);
    // apply old seniority numbers as if MN started at 0 height
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr2Height, 0), consensusParams.nSeniorityLevel2);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr1Height, 0), consensusParams.nSeniorityLevel1);
    // apply old seniority numbers as if MN started at 10000 height
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr2Height+10000, 10000), consensusParams.nSeniorityLevel2);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr1Height+10000, 10000), consensusParams.nSeniorityLevel1);
    // test transition of old seniority numbers
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr1Height + (oldSr2Height-oldSr1Height) - 1, 0), consensusParams.nSeniorityLevel1);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(oldSr1Height + (oldSr2Height-oldSr1Height), 0), consensusParams.nSeniorityLevel2);
    // test transition of new seniority number as if MN started at the NEVM start height
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock+newSr1Height - 1, consensusParams.nNEVMStartBlock), 0);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock+newSr1Height, consensusParams.nNEVMStartBlock), consensusParams.nSeniorityLevel1);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock+newSr1Height + (newSr2Height - newSr1Height) - 1, consensusParams.nNEVMStartBlock), consensusParams.nSeniorityLevel1);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(consensusParams.nNEVMStartBlock+newSr1Height + (newSr2Height - newSr1Height) , consensusParams.nNEVMStartBlock), consensusParams.nSeniorityLevel2);
    // test transition of new seniority number as if MN started before NEVM height
    const int nStartHeight = consensusParams.nNEVMStartBlock - 25000;
    const int nTargetHeight1 = (consensusParams.nNEVMStartBlock + newSr1Height) - (25000/2.5);
    const int nTargetHeight2 = (consensusParams.nNEVMStartBlock + newSr2Height) - (25000/2.5);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(nTargetHeight1 - 1, nStartHeight), 0);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(nTargetHeight1, nStartHeight), consensusParams.nSeniorityLevel1);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(nTargetHeight2 - 1, nStartHeight), consensusParams.nSeniorityLevel1);
    BOOST_CHECK_EQUAL(consensusParams.Seniority(nTargetHeight2, nStartHeight), consensusParams.nSeniorityLevel2);
}
BOOST_AUTO_TEST_CASE(halving_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto consensusParams = chainParams->GetConsensus();
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(100000), 0);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(consensusParams.nSubsidyHalvingInterval), 0);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(consensusParams.nSubsidyHalvingInterval+1), 0);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals((consensusParams.nSubsidyHalvingInterval*2.5) - 1), 0);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(consensusParams.nSubsidyHalvingInterval*2.5), 1);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals((consensusParams.nSubsidyHalvingInterval*2.5) + 1), 1);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(consensusParams.nSubsidyHalvingInterval*2.5 + consensusParams.nSubsidyHalvingInterval*2.5), 2);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(consensusParams.nNEVMStartBlock), 2);
    double forkIntervals = consensusParams.nNEVMStartBlock/(consensusParams.nSubsidyHalvingInterval*2.5);
    int ceilingIntervalFork = ceil(forkIntervals);
    double diffForkInterval = ceilingIntervalFork - forkIntervals;
    int nextIntervalAfterFork = consensusParams.nNEVMStartBlock + diffForkInterval*consensusParams.nSubsidyHalvingInterval;
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork - 1), 2);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork), 3);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork+1), 3);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork + consensusParams.nSubsidyHalvingInterval - 1), 3);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork + consensusParams.nSubsidyHalvingInterval), 4);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork + (consensusParams.nSubsidyHalvingInterval*2) - 1), 4);
    BOOST_CHECK_EQUAL(consensusParams.SubsidyHalvingIntervals(nextIntervalAfterFork + (consensusParams.nSubsidyHalvingInterval*2)), 5);
}
BOOST_AUTO_TEST_CASE(checksyscoinmint_event_log_parsing)
{
    const uint64_t assetGuid = Params().GetConsensus().nSYSXAsset;
    const CAmount outputAmount = 100 * COIN;
    const std::string witnessAddress = "sys1q09vm5lfy0j5reeulh4x5752q25uqqvz34hufdl";

    NEVMMintTxSet setMintTxs;
    CAssetsMap mapAssetIn, mapAssetOut;
    mapAssetOut[assetGuid] = outputAmount;

    // Helper lambda to create a correctly formed CMintSyscoin object
    auto createValidMintSyscoin = [&](const uint64_t assetGuid, const CAmount value, const std::string& syscoinAddr) -> CMintSyscoin {
        CMintSyscoin mint;
        mint.nBlockHash = uint256S("0xbbbb");
        mint.nTxHash = uint256S("0xeeee");
        mint.nTxRoot = uint256S("0xcccc");
        mint.nReceiptRoot = uint256S("0xdddd");
        
        const auto& erc20Manager = Params().GetConsensus().vchSYSXERC20Manager;
        const auto& freezeTopic = Params().GetConsensus().vchTokenFreezeMethod;

        // ABI encode the log data exactly as the validation expects
        std::vector<unsigned char> data;

        // assetGuid
        data.insert(data.end(), 24, 0);
        uint64_t assetGuidBE = htobe64(assetGuid);
        data.insert(data.end(), (unsigned char*)&assetGuidBE, ((unsigned char*)&assetGuidBE) + 8);

        // freezer address (dummy)
        data.insert(data.end(), 12, 0);
        auto freezer = ParseHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        data.insert(data.end(), freezer.begin(), freezer.end());

        // value (uint256)
        data.insert(data.end(), 24, 0);
        uint64_t valueBE = htobe64(value);
        data.insert(data.end(), (unsigned char*)&valueBE, ((unsigned char*)&valueBE) + 8);

        // offset (0x80)
        data.insert(data.end(), 31, 0);
        data.push_back(0x80);

        // string length
        data.insert(data.end(), 31, 0);
        data.push_back(syscoinAddr.size());

        // string data
        data.insert(data.end(), syscoinAddr.begin(), syscoinAddr.end());
        data.insert(data.end(), (32 - (syscoinAddr.size() % 32)), 0);

        // Create RLP log
        dev::RLPStream logs;
        logs.appendList(1);
        logs.appendList(3);
        logs << dev::Address(erc20Manager);
        logs.appendList(1);
        logs << freezeTopic;
        logs << data;

        // Complete receipt RLP
        dev::RLPStream receipt;
        receipt.appendList(4);
        receipt << 1;    // status = success
        receipt << "";   // cumulativeGasUsed
        receipt << "";   // logsBloom
        receipt.appendRaw(logs.out());

        mint.posReceipt = 0;
        auto receiptBytes = receipt.out();
        mint.vchReceiptParentNodes.assign(receiptBytes.begin(), receiptBytes.end());

        // Create dummy valid Tx RLP (for VerifyProof)
        dev::RLPStream txStream;
        txStream.appendList(8);
        txStream << Params().GetConsensus().nNEVMChainID; // chainId
        txStream << ""; // nonce
        txStream << ""; // gasPrice
        txStream << ""; // gasLimit
        txStream << ""; // to address placeholder
        txStream << dev::Address(erc20Manager); // to address (vchSYSXERC20Manager)
        txStream << ""; // value placeholder
        txStream << ""; // data placeholder

        auto txBytes = txStream.out();
        mint.posTx = 0;
        mint.vchTxParentNodes = txBytes; // actual valid minimal RLP to pass VerifyProof

        // Compute the correct tx hash
        std::vector<unsigned char> txHashComputed(dev::sha3(txBytes).asBytes());
        std::reverse(txHashComputed.begin(), txHashComputed.end());
        mint.nTxHash = uint256S(HexStr(txHashComputed));

        // Dummy txpath (trivial path)
        mint.vchTxPath = ParseHex("00");

        return mint;
    };

    CMintSyscoin mintSyscoin = createValidMintSyscoin(assetGuid, outputAmount, witnessAddress);

    TxValidationState state;
    CAmount outputAmountInternal;
    std::string witnessAddressInternal;
    uint64_t assetGuidInternal;

    // Set regtest flag to true to skip txroot/receiptroot DB checks only
    fRegTest = true;

    // Actual test function call
    bool result = CheckSyscoinMintInternal(
        mintSyscoin,
        state,
        false, /*fJustCheck*/
        setMintTxs,
        assetGuidInternal,
        outputAmountInternal,
        witnessAddressInternal
    );

    // Check validation results
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(assetGuidInternal, assetGuid);
    BOOST_CHECK_EQUAL(outputAmountInternal, outputAmount);
    BOOST_CHECK_EQUAL(witnessAddressInternal, witnessAddress);
}


/*BOOST_AUTO_TEST_CASE(nevm_parseabidata)
{
    tfm::format(std::cout,"Running nevm_parseabidata...\n");
    CAmount outputAmount;
    std::string address;

    // 4-byte function selector for freezeBurn(...)
    const std::vector<unsigned char> &expectedMethodHash = ParseHex("ab972f5a");

    // A valid RLP that encodes:
    //  (1) methodHash = ab972f5a
    //  (2) value = 100*COIN in big-endian
    //  (3) assetAddr => dummy 0x1111111111111111111111111111111111111111
    //  (4) tokenId => 0
    //  (5) offset pointer => 0x80
    //  (6) string length => 44
    //  (7) the 44-byte string
    //  (8) zero padding
    const std::vector<unsigned char> &rlpBytes = ParseHex(
        // method hash
        "ab972f5a"
        // value: 0x02540be400 => 10,000,000,000 (100 * COIN)
        "00000000000000000000000000000000000000000000000000000002540be400"
        // assetAddr => 0x111111... in last 20 bytes
        "0000000000000000000000001111111111111111111111111111111111111111"
        // tokenId => 0
        "0000000000000000000000000000000000000000000000000000000000000000"
        // offset pointer => 0x80
        "0000000000000000000000000000000000000000000000000000000000000080"
        // string length => 0x2c (44 decimal)
        "000000000000000000000000000000000000000000000000000000000000002c"
        // 44-byte string => "bcrt1q0fre240sy92mqk8kk7psaea6kt6m5725p7ydcj"
        "62637274317130667265323430737939326d716b386b6b377073616561366b74"
        "366d3537323570377964636a"
        // pad 20 bytes => total 64 after the string length
        "0000000000000000000000000000000000000000"
    );

    // The expected witness address
    std::string expectedAddress = "bcrt1q0fre240sy92mqk8kk7psaea6kt6m5725p7ydcj";

    // Positive test => should succeed
    BOOST_CHECK(parseNEVMMethodInputData(
        expectedMethodHash, 
        rlpBytes, 
        outputAmount, 
        address
    ));
    // Check the parse results
    BOOST_CHECK_EQUAL(outputAmount, 100 * COIN);
    BOOST_CHECK_EQUAL(address, expectedAddress);

    // Negative test #1: Wrong method hash => should fail
    const std::vector<unsigned char> &invalidMethodHash = ParseHex("deadbeef");
    BOOST_CHECK(!parseNEVMMethodInputData(
        invalidMethodHash, 
        rlpBytes, 
        outputAmount, 
        address
    ));

    // Negative test #2: "invalidAddressRlpBytes"
    // We'll cause out-of-bounds by removing the last 8 hex bytes from the final padding.
    // So the string claims length=44, but there's only 36 leftover => parse should fail.
    const std::vector<unsigned char> &invalidAddressRlpBytes = ParseHex(
        "ab972f5a"
        // param1 => 100 * COIN
        "00000000000000000000000000000000000000000000000000000002540be400"
        // param2 => some "invalid" address? Actually doesn't matter; we want out-of-bounds
        "0000000000000000000000009999999999999999999999999999999999999999"
        // param3 => tokenId => 0
        "0000000000000000000000000000000000000000000000000000000000000000"
        // param4 => offset pointer => 0x80
        "0000000000000000000000000000000000000000000000000000000000000080"
        // string length => 44
        "000000000000000000000000000000000000000000000000000000000000002c"
        // string data => let's only provide 32 bytes (should be 44)
        "62637274317130667265323430737939326d716b386b6b3770"
        // no final padding => out-of-bounds read
    );
    BOOST_CHECK(!parseNEVMMethodInputData(
        expectedMethodHash, 
        invalidAddressRlpBytes, 
        outputAmount, 
        address
    ));

    // Negative test #3: "invalidTokenIdRlpBytes"
    // Similarly remove final 8 hex => string is truncated => out-of-bounds => false
    const std::vector<unsigned char> &invalidTokenIdRlpBytes = ParseHex(
        "ab972f5a"
        // param1 => 100 * COIN
        "00000000000000000000000000000000000000000000000000000002540be400"
        // param2 => normal address
        "0000000000000000000000001111111111111111111111111111111111111111"
        // param3 => tokenId => let's pretend it's zero, but it doesn't matter
        "0000000000000000000000000000000000000000000000000000000000000000"
        // param4 => offset pointer => 0x80
        "0000000000000000000000000000000000000000000000000000000000000080"
        // length => 44
        "000000000000000000000000000000000000000000000000000000000000002c"
        // give only 16 bytes of actual string
        "62637274317130667265323430"
        // no leftover => out-of-bounds
    );
    BOOST_CHECK(!parseNEVMMethodInputData(
        expectedMethodHash, 
        invalidTokenIdRlpBytes, 
        outputAmount, 
        address
    ));

    // Negative test #4: "shortStringRlpBytes"
    // We'll make the string length 16 but only provide 8 => out-of-bounds
    const std::vector<unsigned char> &shortStringRlpBytes = ParseHex(
        "ab972f5a"
        "00000000000000000000000000000000000000000000000000000002540be400"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000080"
        // length=16 => 0x10
        "0000000000000000000000000000000000000000000000000000000000000010"
        // provide only 8 bytes => out-of-bounds
        "6263727431713066"
        // remove leftover so parse fails
    );
    BOOST_CHECK(!parseNEVMMethodInputData(
        expectedMethodHash, 
        shortStringRlpBytes, 
        outputAmount, 
        address
    ));

    // Negative test #5: "badPaddingRlpBytes"
    // We'll set length=44 but remove more than 44 from the end. Out-of-bounds read => false
    const std::vector<unsigned char> &badPaddingRlpBytes = ParseHex(
        "ab972f5a"
        "00000000000000000000000000000000000000000000000000000002540be400"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000080"
        // length=44
        "000000000000000000000000000000000000000000000000000000000000002c"
        // Provide exactly 30 bytes of the string => out-of-bounds
        "62637274317130667265323430737939326d716b386b6b"
        // omit the rest => parse fails
    );
    BOOST_CHECK(!parseNEVMMethodInputData(
        expectedMethodHash,  
        badPaddingRlpBytes, 
        outputAmount, 
        address
    ));
}


BOOST_AUTO_TEST_CASE(nevmspv_valid)
{
    tfm::format(std::cout,"Running nevmspv_valid...\n");
    // Read tests from test/data/nevmspv_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // [[spv_root, spv_parent_node, spv_value, spv_path]]

    UniValue tests = read_json(json_tests::nevmspv_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue &test = tests[idx];
        const std::string &strTest = test.write();
        if (test.size() != 4) {
            // ignore comments
            continue;
		} else {
            if ( !test[0].isStr() || !test[1].isStr() || !test[2].isStr() || !test[3].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            std::string spv_tx_root = test[0].get_str();
                std::string spv_parent_nodes = test[1].get_str();
                std::string spv_value = test[2].get_str();
                std::string spv_path = test[3].get_str();

            const std::vector<unsigned char> &vchTxRoot = ParseHex(spv_tx_root);
            dev::RLP rlpTxRoot(&vchTxRoot);
            const std::vector<unsigned char> &vchTxParentNodes = ParseHex(spv_parent_nodes);
            dev::RLP rlpTxParentNodes(&vchTxParentNodes);
            const std::vector<unsigned char> &vchTxValue = ParseHex(spv_value);
            dev::RLP rlpTxValue(&vchTxValue);
            const std::vector<unsigned char> &vchTxPath = ParseHex(spv_path);
            BOOST_CHECK(VerifyProof(&vchTxPath, rlpTxValue, rlpTxParentNodes, rlpTxRoot));
        }
    }
}*/

BOOST_AUTO_TEST_CASE(nevmspv_invalid)
{
    tfm::format(std::cout,"Running nevmspv_invalid...\n");
    // Read tests from test/data/nevmspv_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // [[spv_root, spv_parent_node, spv_value, spv_path]]

    UniValue tests = read_json(json_tests::nevmspv_invalid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue &test = tests[idx];
        const std::string &strTest = test.write();
        if (test.size() != 4) {
            // ignore comments
            continue;
        } else {
            if ( !test[0].isStr() || !test[1].isStr() || !test[2].isStr() || !test[3].isStr()) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }
                    std::string spv_tx_root = test[0].get_str();
                    std::string spv_parent_nodes = test[1].get_str();
                    std::string spv_value = test[2].get_str();
                    std::string spv_path = test[3].get_str();

            const std::vector<unsigned char> &vchTxRoot = ParseHex(spv_tx_root);
            dev::RLP rlpTxRoot(&vchTxRoot);
            const std::vector<unsigned char> &vchTxParentNodes = ParseHex(spv_parent_nodes);
            dev::RLP rlpTxParentNodes(&vchTxParentNodes);
            const std::vector<unsigned char> &vchTxValue = ParseHex(spv_value);
            dev::RLP rlpTxValue(&vchTxValue);
            const std::vector<unsigned char> &vchTxPath = ParseHex(spv_path);
            BOOST_CHECK(!VerifyProof(&vchTxPath, rlpTxValue, rlpTxParentNodes, rlpTxRoot));
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
