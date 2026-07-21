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
#include <primitives/transaction.h>
#include <services/assetconsensus.h>
#include <services/nevmconsensus.h>
#include <util/fs.h>

namespace {
CTransaction MakeNEVMDataTx(const std::vector<uint8_t>& version_hash, const std::vector<uint8_t>& data)
{
    CNEVMData nevmData;
    nevmData.vchVersionHash = version_hash;
    std::vector<unsigned char> payload;
    nevmData.SerializeData(payload);

    CMutableTransaction mtx;
    mtx.nVersion = SYSCOIN_TX_VERSION_NEVM_DATA_SHA3;
    mtx.vout.emplace_back(0, CScript() << OP_RETURN << payload);
    mtx.vout.back().vchNEVMData = data;
    return CTransaction{mtx};
}

MapPoDAPayloadMeta MakePoDAMeta(const uint256& txid, uint32_t size, int64_t median_time)
{
    MapPoDAPayloadMeta meta{txid, size, median_time};
    meta.vchNEVMData = std::make_shared<const std::vector<uint8_t>>(size, uint8_t{0});
    return meta;
}
} // namespace

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

BOOST_AUTO_TEST_CASE(nevmspv_rejects_empty_compact_path)
{
    // parentNodes contains one two-item MPT node whose compact-path payload is empty.
    const std::vector<unsigned char> encoded_node{0xc2, 0x80, 0x80};
    const std::vector<unsigned char> encoded_parent_nodes{0xc3, 0xc2, 0x80, 0x80};
    const dev::RLP parent_nodes(&encoded_parent_nodes);
    const dev::h256 node_hash = dev::sha3(
        dev::bytesConstRef(encoded_node.data(), encoded_node.size()));
    const dev::bytes node_hash_bytes = node_hash.asBytes();
    dev::RLPStream root_stream;
    root_stream.append(dev::bytesConstRef(node_hash_bytes.data(), node_hash_bytes.size()));
    const dev::RLP root(root_stream.out());

    const std::vector<unsigned char> encoded_value{0x80};
    const dev::RLP value(&encoded_value);
    const std::vector<unsigned char> path;
    BOOST_CHECK(!VerifyProof(
        dev::bytesConstRef(path.data(), path.size()), value, parent_nodes, root));
}

BOOST_AUTO_TEST_CASE(nevmspv_authenticates_envelope_type)
{
    auto verify = [](const std::optional<uint8_t>& type) {
        const dev::bytes payload{0xc0}; // Empty RLP list.
        dev::bytes trie_value;
        if (type.has_value()) {
            trie_value.push_back(*type);
        }
        trie_value.insert(trie_value.end(), payload.begin(), payload.end());

        dev::RLPStream leaf(2);
        leaf.append(dev::bytes{0x20}); // Leaf with an empty remaining path.
        leaf.append(trie_value);
        const dev::bytes leaf_data = leaf.out();

        dev::RLPStream parents(1);
        parents.appendRaw(leaf_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);

        const dev::h256 node_hash = dev::sha3(
            dev::bytesConstRef(leaf_data.data(), leaf_data.size()));
        const dev::bytes root_bytes = node_hash.asBytes();
        dev::RLPStream root_stream;
        root_stream.append(dev::bytesConstRef(root_bytes.data(), root_bytes.size()));
        const dev::RLP root(root_stream.out());
        const dev::RLP value(payload);
        const dev::bytes path;

        std::optional<uint8_t> parsed_type;
        BOOST_REQUIRE(VerifyProof(
            dev::bytesConstRef(path.data(), path.size()), value, parent_nodes, root,
            &parsed_type));
        BOOST_CHECK(parsed_type == type);
    };

    verify(std::nullopt);
    verify(uint8_t{1});
    verify(uint8_t{2});
    verify(uint8_t{0x7f});
}

BOOST_AUTO_TEST_CASE(nevmspv_requires_hp_leaf_extension_flags)
{
    // Hex-prefix flag nibble: 0/1 = extension (child ref), 2/3 = leaf (value).
    // VerifyProof must use that bit — not merely whether the remaining path is empty.
    const dev::bytes payload{0xc0};
    const dev::RLP value(payload);
    const dev::bytes empty_path;

    auto make_root_bytes = [](const dev::bytes& node_data) {
        const dev::bytes root_hash = dev::sha3(
            dev::bytesConstRef(node_data.data(), node_data.size())).asBytes();
        dev::RLPStream root_stream;
        root_stream.append(dev::bytesConstRef(root_hash.data(), root_hash.size()));
        return root_stream.out();
    };

    // 1) Empty even extension (noncanonical) must not authenticate as a value.
    {
        dev::RLPStream extension(2);
        extension.append(dev::bytes{0x00}); // extension, even, empty path
        extension.append(payload);
        const dev::bytes node_data = extension.out();

        dev::RLPStream parents(1);
        parents.appendRaw(node_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(node_data);
        const dev::RLP root(root_data);

        BOOST_CHECK_MESSAGE(
            !VerifyProof(dev::bytesConstRef(empty_path.data(), empty_path.size()),
                         value, parent_nodes, root),
            "empty extension must not authenticate");
    }

    // 2) Empty-path leaf (flag 2) must still authenticate.
    {
        dev::RLPStream leaf(2);
        leaf.append(dev::bytes{0x20}); // leaf, even, empty path
        leaf.append(payload);
        const dev::bytes node_data = leaf.out();

        dev::RLPStream parents(1);
        parents.appendRaw(node_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(node_data);
        const dev::RLP root(root_data);

        BOOST_CHECK(VerifyProof(
            dev::bytesConstRef(empty_path.data(), empty_path.size()),
            value, parent_nodes, root));
    }

    // 3) Nonempty extension that consumes the full key, then a branch value.
    //    Old path-exhaustion logic compared the branch hash to the value.
    {
        const dev::bytes path{0xab}; // hex path nibbles "ab"

        dev::RLPStream branch(17);
        branch.append(dev::bytes(32, 0x42)); // unrelated hashed child
        for (int i = 1; i < 16; ++i) {
            branch.append(dev::bytes{});
        }
        branch.append(payload); // branch value slot
        const dev::bytes branch_data = branch.out();
        const dev::bytes branch_hash = dev::sha3(
            dev::bytesConstRef(branch_data.data(), branch_data.size())).asBytes();

        dev::RLPStream extension(2);
        extension.append(dev::bytes{0x00, 0xab}); // even extension path "ab"
        extension.append(branch_hash);
        const dev::bytes ext_data = extension.out();

        dev::RLPStream parents(2);
        parents.appendRaw(ext_data);
        parents.appendRaw(branch_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(ext_data);
        const dev::RLP root(root_data);

        BOOST_CHECK_MESSAGE(
            VerifyProof(dev::bytesConstRef(path.data(), path.size()),
                        value, parent_nodes, root),
            "nonempty extension must descend into branch value");
    }

    // 4) Leaf flag with path still remaining must reject, even if the leaf
    //    "value" is the keccak of a following node that would complete the path.
    {
        const dev::bytes path{0xab}; // hex path nibbles "ab"

        dev::RLPStream real_leaf(2);
        real_leaf.append(dev::bytes{0x20, 0xab}); // leaf consuming "ab"
        real_leaf.append(payload);
        const dev::bytes real_leaf_data = real_leaf.out();
        const dev::bytes real_leaf_hash = dev::sha3(
            dev::bytesConstRef(real_leaf_data.data(), real_leaf_data.size())).asBytes();

        // Mis-labeled leaf used as if it were an extension.
        dev::RLPStream fake_leaf(2);
        fake_leaf.append(dev::bytes{0x20}); // leaf flag, empty path
        fake_leaf.append(real_leaf_hash);
        const dev::bytes fake_leaf_data = fake_leaf.out();

        dev::RLPStream parents(2);
        parents.appendRaw(fake_leaf_data);
        parents.appendRaw(real_leaf_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(fake_leaf_data);
        const dev::RLP root(root_data);

        BOOST_CHECK_MESSAGE(
            !VerifyProof(dev::bytesConstRef(path.data(), path.size()),
                         value, parent_nodes, root),
            "leaf flag must not be followed as an extension");
    }

    // 5) Odd flags: extension 1a → leaf 3b.
    {
        const dev::bytes path{0xab};

        dev::RLPStream leaf(2);
        leaf.append(dev::bytes{0x3b}); // odd leaf, remaining nibble "b"
        leaf.append(payload);
        const dev::bytes leaf_data = leaf.out();
        const dev::bytes leaf_hash = dev::sha3(
            dev::bytesConstRef(leaf_data.data(), leaf_data.size())).asBytes();

        dev::RLPStream extension(2);
        extension.append(dev::bytes{0x1a}); // odd extension, nibble "a"
        extension.append(leaf_hash);
        const dev::bytes ext_data = extension.out();

        dev::RLPStream parents(2);
        parents.appendRaw(ext_data);
        parents.appendRaw(leaf_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(ext_data);
        const dev::RLP root(root_data);

        BOOST_CHECK(VerifyProof(
            dev::bytesConstRef(path.data(), path.size()), value, parent_nodes, root));
    }

    // 6) Invalid HP flag nibble (> 3) must reject.
    {
        dev::RLPStream node(2);
        node.append(dev::bytes{0x40}); // flag 4
        node.append(payload);
        const dev::bytes node_data = node.out();

        dev::RLPStream parents(1);
        parents.appendRaw(node_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(node_data);
        const dev::RLP root(root_data);

        BOOST_CHECK(!VerifyProof(
            dev::bytesConstRef(empty_path.data(), empty_path.size()),
            value, parent_nodes, root));
    }

    // 7) Even encoding with nonzero padding nibble must reject.
    {
        dev::RLPStream node(2);
        node.append(dev::bytes{0x2f}); // leaf flag with nonzero pad
        node.append(payload);
        const dev::bytes node_data = node.out();

        dev::RLPStream parents(1);
        parents.appendRaw(node_data);
        const dev::bytes parent_data = parents.out();
        const dev::RLP parent_nodes(parent_data);
        const dev::bytes root_data = make_root_bytes(node_data);
        const dev::RLP root(root_data);

        BOOST_CHECK(!VerifyProof(
            dev::bytesConstRef(empty_path.data(), empty_path.size()),
            value, parent_nodes, root));
    }
}

BOOST_AUTO_TEST_CASE(nevm_blob_versionhash_formats_and_hashes)
{
    const std::vector<uint8_t> data{'a', 'b', 'c'};
    const auto keccak = dev::sha3(data).asBytes();
    BOOST_CHECK_EQUAL(
        HexStr(keccak),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");

    const auto blake = dev::blake2s(dev::bytesConstRef(&data)).asBytes();
    BOOST_CHECK_EQUAL(
        HexStr(blake),
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

    std::vector<uint8_t> versioned_blake;
    versioned_blake.reserve(NEVM_DATA_VERSIONED_HASH_SIZE);
    versioned_blake.push_back(NEVM_DATA_BLAKE2S_VERSION_BYTE);
    versioned_blake.insert(versioned_blake.end(), blake.begin(), blake.end());

    BOOST_CHECK(IsValidNEVMVersionHash(keccak));
    BOOST_CHECK(IsValidNEVMVersionHash(versioned_blake));

    auto invalid_versioned = versioned_blake;
    invalid_versioned[0] = 0x02;
    BOOST_CHECK(!IsValidNEVMVersionHash(invalid_versioned));

    std::vector<uint8_t> invalid_short(31, 0);
    BOOST_CHECK(!IsValidNEVMVersionHash(invalid_short));

    uint8_t hash_type = NEVM_DATA_LEGACY_VERSION_BYTE;
    std::vector<uint8_t> digest;
    BOOST_CHECK(DecodeNEVMVersionHash(keccak, hash_type, digest));
    BOOST_CHECK_EQUAL(hash_type, NEVM_DATA_LEGACY_VERSION_BYTE);
    BOOST_CHECK(digest == keccak);

    BOOST_CHECK(DecodeNEVMVersionHash(versioned_blake, hash_type, digest));
    BOOST_CHECK_EQUAL(hash_type, NEVM_DATA_BLAKE2S_VERSION_BYTE);
    BOOST_CHECK(digest == blake);

    BOOST_CHECK(EncodeNEVMVersionHash(keccak, NEVM_DATA_LEGACY_VERSION_BYTE) == keccak);
    BOOST_CHECK(EncodeNEVMVersionHash(blake, NEVM_DATA_BLAKE2S_VERSION_BYTE) == versioned_blake);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(nevm_poda_validation_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(nevm_blob_sidecar_failures_are_auxiliary)
{
    pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
        .path = "poda_meta",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});
    pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
        .path = "poda_blob",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});

    const std::vector<uint8_t> good_data{'g', 'o', 'o', 'd'};
    const std::vector<uint8_t> bad_data{'b', 'a', 'd'};
    const std::vector<uint8_t> version_hash = dev::sha3(good_data).asBytes();
    PoDAMAPMemory mapPoDA;

    BOOST_CHECK_EQUAL(
        ProcessNEVMData(m_node.chainman->m_blockman, MakeNEVMDataTx(version_hash, bad_data), /*nMedianTime=*/100, /*nTimeNow=*/100, mapPoDA),
        ProcessNEVMDataResult::AUX_DATA_INVALID);
    BOOST_CHECK(mapPoDA.empty());

    BOOST_CHECK_EQUAL(
        ProcessNEVMData(m_node.chainman->m_blockman, MakeNEVMDataTx(version_hash, good_data), /*nMedianTime=*/100, /*nTimeNow=*/100, mapPoDA),
        ProcessNEVMDataResult::VALID);
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    mapPoDA.clear();
    BOOST_CHECK(pnevmdatadb->BlobExists(version_hash));

    BOOST_CHECK_EQUAL(
        ProcessNEVMData(m_node.chainman->m_blockman, MakeNEVMDataTx(version_hash, bad_data), /*nMedianTime=*/100, /*nTimeNow=*/100, mapPoDA),
        ProcessNEVMDataResult::AUX_DATA_INVALID);
    BOOST_CHECK(mapPoDA.empty());

    std::vector<CTransactionRef> txs;
    txs.emplace_back(MakeTransactionRef(CMutableTransaction{}));
    for (int i = 0; i <= MAX_DATA_BLOBS; ++i) {
        txs.emplace_back(MakeTransactionRef(MakeNEVMDataTx(version_hash, good_data)));
    }
    CBlock too_many_blobs;
    too_many_blobs.vtx = txs;
    mapPoDA.clear();
    BOOST_CHECK_EQUAL(
        ProcessNEVMData(m_node.chainman->m_blockman, too_many_blobs, /*nMedianTime=*/100, /*nTimeNow=*/100, mapPoDA),
        ProcessNEVMDataResult::CONSENSUS_INVALID);
}

BOOST_AUTO_TEST_CASE(nevm_duplicate_blob_metadata_refresh_rules)
{
    pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
        .path = "poda_meta_duplicates",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});
    pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
        .path = "poda_blob_duplicates",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});

    const std::vector<uint8_t> version_hash = dev::sha3(std::vector<uint8_t>{'d', 'a', 't', 'a'}).asBytes();
    const uint256 original_txid = uint256S("01");
    const uint256 small_txid = uint256S("02");
    const uint256 mempool_txid = uint256S("03");
    const uint256 block_txid = uint256S("04");

    PoDAMAPMemory mapPoDA;
    mapPoDA.emplace(version_hash, MakePoDAMeta(original_txid, /*size=*/100, /*median_time=*/1000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(/*nMedianTime=*/1000));

    MapPoDAPayloadMeta meta;
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, original_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 1000);

    mapPoDA.clear();
    mapPoDA.emplace(version_hash, MakePoDAMeta(small_txid, /*size=*/10, /*median_time=*/2000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, original_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 1000);

    mapPoDA.clear();
    mapPoDA.emplace(version_hash, MakePoDAMeta(mempool_txid, /*size=*/100, /*median_time=*/3000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Mempool);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, original_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 1000);

    mapPoDA.clear();
    mapPoDA.emplace(version_hash, MakePoDAMeta(block_txid, /*size=*/100, /*median_time=*/4000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, block_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);

    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(version_hash, original_txid));
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, block_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);
    BOOST_CHECK(pnevmdatadb->Exists(version_hash));
    BOOST_CHECK(pnevmdatablobdb->Exists(version_hash));

    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(/*nMedianTime=*/4000));
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, block_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(nevm_mint_replay_lifecycle_tests, BasicTestingSetup)

// nevmminttx markers must survive a non-wipe reopen (geth-aux rebuild path).
BOOST_AUTO_TEST_CASE(mint_replay_db_survives_non_wipe_reopen)
{
    const fs::path db_dir = gArgs.GetDataDirNet() / "nevmminttx_wipe_policy";
    fs::remove_all(db_dir);

    const uint256 mint_tx = uint256S(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    {
        CNEVMMintedTxDB mint_db({
            .path = db_dir,
            .cache_bytes = static_cast<size_t>(1 << 20),
            .memory_only = false,
            .wipe_data = true});
        mint_db.FlushDataToCache({mint_tx});
        BOOST_REQUIRE(mint_db.FlushCacheToDisk(/*CHUNK_ITEMS=*/256, /*fSync=*/true));
        BOOST_CHECK(mint_db.ExistsTx(mint_tx));
    }

    {
        CNEVMMintedTxDB mint_db({
            .path = db_dir,
            .cache_bytes = static_cast<size_t>(1 << 20),
            .memory_only = false,
            .wipe_data = false});
        BOOST_CHECK_MESSAGE(
            mint_db.ExistsTx(mint_tx),
            "Mint replay markers must survive a non-wipe database reopen");
    }

    {
        // Chainstate rebuild path clears markers.
        CNEVMMintedTxDB mint_db({
            .path = db_dir,
            .cache_bytes = static_cast<size_t>(1 << 20),
            .memory_only = false,
            .wipe_data = true});
        BOOST_CHECK(!mint_db.ExistsTx(mint_tx));
    }
}

// Disconnect crash-order: persist pending additions before selective erase.
BOOST_AUTO_TEST_CASE(mint_replay_flush_additions_before_selective_erase)
{
    const fs::path db_dir = gArgs.GetDataDirNet() / "nevmminttx_crash_order";
    fs::remove_all(db_dir);

    const uint256 active_mint = uint256S(
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const uint256 disconnect_mint = uint256S(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    CNEVMMintedTxDB mint_db({
        .path = db_dir,
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = false,
        .wipe_data = true});

    mint_db.FlushDataToCache({active_mint, disconnect_mint});
    BOOST_CHECK(mint_db.ExistsTx(active_mint));
    BOOST_CHECK(mint_db.ExistsTx(disconnect_mint));

    BOOST_REQUIRE(mint_db.FlushCacheToDisk(/*CHUNK_ITEMS=*/256, /*fSync=*/true));
    BOOST_REQUIRE(mint_db.FlushErase({disconnect_mint}));

    BOOST_CHECK_MESSAGE(mint_db.ExistsTx(active_mint),
                        "Unrelated active mint marker must remain after disconnect erase");
    BOOST_CHECK(!mint_db.ExistsTx(disconnect_mint));
}

// ReplayBlocks erase set: old-branch mints minus mints also on the new branch.
BOOST_AUTO_TEST_CASE(mint_replay_disconnect_only_excludes_reconnected)
{
    const uint256 old_only = uint256S(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    const uint256 both = uint256S(
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    const uint256 new_only = uint256S(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    NEVMMintTxSet disconnect{old_only, both};
    NEVMMintTxSet connect{both, new_only};
    NEVMMintTxSet disconnect_only;
    for (const auto& hash : disconnect) {
        if (!connect.count(hash)) {
            disconnect_only.insert(hash);
        }
    }

    BOOST_CHECK_EQUAL(disconnect_only.size(), 1U);
    BOOST_CHECK(disconnect_only.count(old_only));
    BOOST_CHECK(!disconnect_only.count(both));
    BOOST_CHECK(!disconnect_only.count(new_only));
}

BOOST_AUTO_TEST_SUITE_END()
