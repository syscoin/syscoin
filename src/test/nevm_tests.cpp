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
        const std::string strTest = test.write();
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

            const std::vector<unsigned char> vchTxRoot = ParseHex(spv_tx_root);
            dev::RLP rlpTxRoot(&vchTxRoot);
            const std::vector<unsigned char> vchTxParentNodes = ParseHex(spv_parent_nodes);
            dev::RLP rlpTxParentNodes(&vchTxParentNodes);
            const std::vector<unsigned char> vchTxValue = ParseHex(spv_value);
            dev::RLP rlpTxValue(&vchTxValue);
            const std::vector<unsigned char> vchTxPath = ParseHex(spv_path);
            dev::bytesConstRef vchTxPathRef(vchTxPath.data(), vchTxPath.size());
            BOOST_CHECK(VerifyProof(vchTxPathRef, rlpTxValue, rlpTxParentNodes, rlpTxRoot));
        }
    }
}

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
        const std::string strTest = test.write();
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

            const std::vector<unsigned char> vchTxRoot = ParseHex(spv_tx_root);
            dev::RLP rlpTxRoot(&vchTxRoot);
            const std::vector<unsigned char> vchTxParentNodes = ParseHex(spv_parent_nodes);
            dev::RLP rlpTxParentNodes(&vchTxParentNodes);
            const std::vector<unsigned char> vchTxValue = ParseHex(spv_value);
            dev::RLP rlpTxValue(&vchTxValue);
            const std::vector<unsigned char> vchTxPath = ParseHex(spv_path);
            dev::bytesConstRef vchTxPathRef(vchTxPath.data(), vchTxPath.size());
            BOOST_CHECK(!VerifyProof(vchTxPathRef, rlpTxValue, rlpTxParentNodes, rlpTxRoot));
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
