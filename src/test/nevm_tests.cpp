#include <boost/test/unit_test.hpp>
#include <test/data/nevmspv_valid.json.h>
#include <test/data/nevmspv_invalid.json.h>

#include <uint256.h>
#include <util/strencodings.h>
#include <nevm/nevm.h>
#include <nevm/common.h>
#include <nevm/rlp.h>
#include <nevm/response.h>
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

#include <array>
#include <cstddef>
// SYSCOIN: overflow boundary coverage for deferred NEVM disconnects.
#include <limits>
#include <optional> // SYSCOIN: explicit canonical-root recovery results.
#include <utility>
#include <vector>

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
BOOST_AUTO_TEST_CASE(nevm_rejection_response_requires_exact_canonical_pair)
{
    const auto nevm_hash{uint256S(std::string(64, 'a'))};
    const auto syscoin_hash{uint256S(std::string(64, 'b'))};
    const std::string canonical{"invalid:" + nevm_hash.GetHex() + ":" + syscoin_hash.GetHex()};
    const auto parsed{ParseNEVMBlockReject(canonical)};
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->nevm_hash == nevm_hash);
    BOOST_CHECK(parsed->syscoin_hash == syscoin_hash);

    std::string uppercase{canonical};
    uppercase[8] = 'A';
    std::string nonhex{canonical};
    nonhex.back() = 'g';
    const std::array<std::string, 9> noncanonical{{
        "", "invalid", canonical.substr(0, canonical.size() - 1),
        "error:" + canonical, canonical + ":detail", canonical + "\n",
        "invalid:0x" + nevm_hash.GetHex() + ":" + syscoin_hash.GetHex(),
        uppercase, nonhex}};
    for (const auto& response : noncanonical) {
        BOOST_TEST_CONTEXT(response) {
            BOOST_CHECK(!ParseNEVMBlockReject(response).has_value());
        }
    }
    // The protocol preserves the pair; ancestry and zero-hash semantics are
    // checked against Core state by the receiving validation path.
    const auto zero_pair{ParseNEVMBlockReject(
        "invalid:" + uint256{}.GetHex() + ":" + uint256{}.GetHex())};
    BOOST_REQUIRE(zero_pair.has_value());
    BOOST_CHECK(zero_pair->nevm_hash.IsNull());
    BOOST_CHECK(zero_pair->syscoin_hash.IsNull());
}

BOOST_AUTO_TEST_CASE(nevm_payload_rejection_is_distinct_and_binds_exact_bytes)
{
    uint256 nevm_hash, tx_root, receipt_root, syscoin_hash;
    std::array<uint256*, 4> context{&nevm_hash, &tx_root, &receipt_root, &syscoin_hash};
    uint8_t next{0};
    for (auto* hash : context) {
        for (auto& byte : *hash) byte = next++;
    }
    const std::string fixture{"benign local fingerprint fixture"};
    const std::vector<uint8_t> bytes{fixture.begin(), fixture.end()};
    const auto fingerprint{NEVMPayloadFingerprint(
        nevm_hash, tx_root, receipt_root, syscoin_hash, bytes)};
    // Shared known-answer vector with Geth; no payload parsing or network I/O.
    BOOST_CHECK_EQUAL(HexStr(fingerprint),
        "40eedc11769e15ed1de925895606a70fee885b59b12bb7e9d72f5e089ec1c0e8");
    const std::string token{"payload-invalid:" + nevm_hash.GetHex() + ":" +
        syscoin_hash.GetHex() + ":" + fingerprint.GetHex()};
    const auto parsed{ParseNEVMBlockReject(token)};
    BOOST_REQUIRE(parsed);
    BOOST_CHECK(parsed->IsPayload());
    BOOST_CHECK(parsed->nevm_hash == nevm_hash);
    BOOST_CHECK(parsed->syscoin_hash == syscoin_hash);
    BOOST_CHECK(parsed->payload_hash == fingerprint);
    const auto consensus{ParseNEVMBlockReject(
        "invalid:" + nevm_hash.GetHex() + ":" + syscoin_hash.GetHex())};
    BOOST_REQUIRE(consensus);
    BOOST_CHECK(!consensus->IsPayload());
    for (const auto& response : {token + "\n", "error:" + token,
            token.substr(0, token.size() - 1), token + ":extra",
            token.substr(0, token.size() - 1) + "A"}) {
        BOOST_CHECK(!ParseNEVMBlockReject(response));
    }
    auto different{bytes};
    different.back() ^= 1;
    BOOST_CHECK(fingerprint != NEVMPayloadFingerprint(
        nevm_hash, tx_root, receipt_root, syscoin_hash, different));
    BOOST_CHECK(fingerprint != NEVMPayloadFingerprint(
        nevm_hash, receipt_root, tx_root, syscoin_hash, bytes));
}

BOOST_AUTO_TEST_CASE(preseal_disconnect_tracks_only_geth_applied_prefix)
{
    // SYSCOIN: Geth count N means heights [start, start + N) were applied.
    BOOST_CHECK(!*IsNEVMBlockAppliedForDisconnect(100, 0, 100));
    BOOST_CHECK(*IsNEVMBlockAppliedForDisconnect(100, 1, 100));
    BOOST_CHECK(!*IsNEVMBlockAppliedForDisconnect(100, 1, 101));
    BOOST_CHECK(*IsNEVMBlockAppliedForDisconnect(100, 8, 107));
    BOOST_CHECK(!*IsNEVMBlockAppliedForDisconnect(100, 8, 108));
    BOOST_CHECK(!IsNEVMBlockAppliedForDisconnect(
        std::numeric_limits<int64_t>::max(), 1, 100));

    // SYSCOIN: Equal height is insufficient: replay completes only when Geth
    // reports the exact paired Syscoin hash for that applied boundary.
    const uint256 active_hash{uint256::ONEV};
    uint256 side_hash{active_hash};
    side_hash.begin()[1] = 1;
    BOOST_CHECK(DoesNEVMBlockInfoMatchSyscoinBlock(
        100, 8, 107, active_hash, active_hash));
    BOOST_CHECK(!DoesNEVMBlockInfoMatchSyscoinBlock(
        100, 8, 107, side_hash, active_hash));
    BOOST_CHECK(!DoesNEVMBlockInfoMatchSyscoinBlock(
        100, 8, 108, active_hash, active_hash));
    BOOST_CHECK(!DoesNEVMBlockInfoMatchSyscoinBlock(
        100, 0, 99, uint256{}, uint256{}));
}

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

BOOST_AUTO_TEST_CASE(blake2s_rfc7693_block_boundaries)
{
    const std::array<std::pair<std::size_t, const char*>, 5> vectors{{
        {0, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
        {64, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"},
        {65, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"},
        {128, "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"},
        {256, "5fdeb59f681d975f52c8e69c5502e02a12a3afcc5836ba58f42784c439228781"},
    }};
    for (const auto& [size, expected] : vectors) {
        std::vector<uint8_t> input(size);
        for (std::size_t i{0}; i < input.size(); ++i) {
            input[i] = static_cast<uint8_t>(i);
        }
        const auto digest = dev::blake2s(dev::bytesConstRef(&input)).asBytes();
        BOOST_CHECK_EQUAL(HexStr(digest), expected);
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(nevm_poda_validation_tests)

BOOST_AUTO_TEST_CASE(nevm_blob_expiry_uses_active_tip_mtp)
{
    constexpr int64_t BLOB_MTP{1'000};
    BOOST_CHECK(!IsNEVMDataExpired(
        BLOB_MTP + NEVM_DATA_EXPIRE_TIME, BLOB_MTP));
    BOOST_CHECK(IsNEVMDataExpired(
        BLOB_MTP + NEVM_DATA_EXPIRE_TIME + 1, BLOB_MTP));
    BOOST_CHECK(!IsNEVMDataExpired(BLOB_MTP - 1, BLOB_MTP));
    BOOST_CHECK(!IsNEVMDataExpired(
        std::numeric_limits<int64_t>::max(),
        std::numeric_limits<int64_t>::max() - NEVM_DATA_EXPIRE_TIME + 1));
}

BOOST_FIXTURE_TEST_CASE(nevm_blob_sidecar_failures_are_auxiliary, RegTestingSetup)
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

BOOST_FIXTURE_TEST_CASE(nevm_duplicate_blob_metadata_refresh_rules, RegTestingSetup)
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
    const uint256 older_block_txid = uint256S("05");
    const uint256 equal_larger_txid = uint256S("06");
    const uint256 equal_smaller_txid = uint256S("03");

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
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(/*nMedianTime=*/4000));

    mapPoDA.clear();
    mapPoDA.emplace(
        version_hash,
        MakePoDAMeta(older_block_txid, /*size=*/100, /*median_time=*/3500));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, block_txid);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);

    mapPoDA.clear();
    mapPoDA.emplace(
        version_hash,
        MakePoDAMeta(equal_larger_txid, /*size=*/100, /*median_time=*/4000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, block_txid);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);

    mapPoDA.clear();
    mapPoDA.emplace(
        version_hash,
        MakePoDAMeta(equal_smaller_txid, /*size=*/100, /*median_time=*/4000));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, equal_smaller_txid);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);

    BOOST_REQUIRE(pnevmdatadb->FlushMempoolErase(version_hash, original_txid));
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, equal_smaller_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);
    BOOST_CHECK(pnevmdatadb->Exists(version_hash));
    BOOST_CHECK(pnevmdatablobdb->Exists(version_hash));

    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(/*nMedianTime=*/4000));
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, equal_smaller_txid);
    BOOST_CHECK_EQUAL(meta.nSize, 100);
    BOOST_CHECK_EQUAL(meta.nMedianTime, 4000);
}

BOOST_FIXTURE_TEST_CASE(nevm_blob_pruning_uses_cache_as_disk_overlay, RegTestingSetup)
{
    pnevmdatadb = std::make_unique<CNEVMDataDB>(DBParams{
        .path = "poda_meta_prune_overlay",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});
    pnevmdatablobdb = std::make_unique<CNEVMDataBlobDB>(DBParams{
        .path = "poda_blob_prune_overlay",
        .cache_bytes = static_cast<size_t>(1 << 20),
        .memory_only = true,
        .wipe_data = true});

    const std::vector<uint8_t> version_hash =
        dev::sha3(std::vector<uint8_t>{'o', 'v', 'e', 'r', 'l', 'a', 'y'}).asBytes();
    constexpr uint32_t DATA_SIZE{64};
    constexpr int64_t STALE_MTP{1'000};
    constexpr int64_t REFRESHED_MTP{STALE_MTP + NEVM_DATA_EXPIRE_TIME};
    constexpr int64_t PRUNE_MTP{STALE_MTP + NEVM_DATA_EXPIRE_TIME + 1};
    const uint256 stale_txid = uint256S("11");
    const uint256 refreshed_txid = uint256S("12");

    PoDAMAPMemory mapPoDA;
    mapPoDA.emplace(
        version_hash, MakePoDAMeta(stale_txid, DATA_SIZE, STALE_MTP));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(STALE_MTP));

    mapPoDA.clear();
    mapPoDA.emplace(
        version_hash,
        MakePoDAMeta(refreshed_txid, DATA_SIZE, REFRESHED_MTP));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);

    // SYSCOIN: the refreshed cache value shadows the expired disk value; a
    // ChainLock prune must retain both its metadata and content bytes.
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(PRUNE_MTP));
    MapPoDAPayloadMeta meta;
    BOOST_REQUIRE(pnevmdatadb->GetBlobMetaData(version_hash, meta));
    BOOST_CHECK_EQUAL(meta.txid, refreshed_txid);
    BOOST_CHECK_EQUAL(meta.nMedianTime, REFRESHED_MTP);
    BOOST_CHECK(pnevmdatablobdb->Exists(version_hash));

    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(PRUNE_MTP));
    BOOST_CHECK(pnevmdatadb->Exists(version_hash));
    BOOST_CHECK(pnevmdatablobdb->Exists(version_hash));

    constexpr int64_t DISK_MTP{1'000};
    constexpr int64_t CACHE_MTP{10'000};
    constexpr int64_t SECOND_PRUNE_MTP{
        CACHE_MTP + NEVM_DATA_EXPIRE_TIME + 1};
    const std::vector<uint8_t> expired_version_hash =
        dev::sha3(std::vector<uint8_t>{'e', 'x', 'p', 'i', 'r', 'e', 'd'}).asBytes();
    const uint256 disk_txid = uint256S("21");
    const uint256 cache_txid = uint256S("22");

    mapPoDA.clear();
    mapPoDA.emplace(
        expired_version_hash,
        MakePoDAMeta(disk_txid, DATA_SIZE, DISK_MTP));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);
    BOOST_REQUIRE(pnevmdatadb->FlushCacheToDisk(DISK_MTP));

    mapPoDA.clear();
    mapPoDA.emplace(
        expired_version_hash,
        MakePoDAMeta(cache_txid, DATA_SIZE, CACHE_MTP));
    pnevmdatadb->FlushDataToCache(mapPoDA, PoDAFlushSource::Block);

    // SYSCOIN: an expired cache value also shadows disk metadata. Pruning must
    // erase both databases instead of exposing metadata for missing bytes.
    BOOST_REQUIRE(pnevmdatadb->PruneStandalone(SECOND_PRUNE_MTP));
    BOOST_CHECK(!pnevmdatadb->GetBlobMetaData(expired_version_hash, meta));
    BOOST_CHECK(!pnevmdatadb->Exists(expired_version_hash));
    BOOST_CHECK(!pnevmdatablobdb->Exists(expired_version_hash));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(nevm_mint_replay_lifecycle_tests)

// nevmminttx markers must survive a non-wipe reopen (geth-aux rebuild path).
BOOST_FIXTURE_TEST_CASE(mint_replay_db_survives_non_wipe_reopen, BasicTestingSetup)
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
BOOST_FIXTURE_TEST_CASE(mint_replay_flush_additions_before_selective_erase, BasicTestingSetup)
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
BOOST_FIXTURE_TEST_CASE(mint_replay_disconnect_only_excludes_reconnected, BasicTestingSetup)
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

// SYSCOIN BEGIN: Exercise real NEVM cache classes with failed batch writes.
namespace {
template <typename Database>
class FailingNEVMCacheDB final : public Database
{
public:
    using Database::Database;
    std::vector<bool> writes;

    void FailNextWrite(bool throw_error)
    {
        m_fail_call = writes.size() + 1;
        m_throw_error = throw_error;
    }

protected:
    bool WriteCacheBatch(CDBBatch& batch, bool sync) override
    {
        writes.push_back(sync);
        if (writes.size() == m_fail_call) {
            if (m_throw_error) throw dbwrapper_error("NEVM cache test write failure");
            return false;
        }
        return CDBWrapper::WriteBatch(batch, sync);
    }

private:
    std::size_t m_fail_call{0};
    bool m_throw_error{false};
};

uint256 NEVMCacheTestKey(unsigned char value)
{
    uint256 key;
    key.begin()[0] = value;
    return key;
}

void StageNEVMCacheValue(CNEVMMintedTxDB& db, const uint256& key, unsigned char)
{
    db.FlushDataToCache({key});
}

void StageNEVMCacheValue(CNEVMTxRootsDB& db, const uint256& key, unsigned char value)
{
    db.FlushDataToCache({{key, NEVMTxRoot{NEVMCacheTestKey(value), NEVMCacheTestKey(value + 1)}}});
}

bool NEVMCacheValueMatches(CNEVMMintedTxDB& db, const uint256& key, unsigned char)
{
    return db.ExistsTx(key);
}

bool NEVMCacheValueMatches(CNEVMTxRootsDB& db, const uint256& key, unsigned char value)
{
    NEVMTxRoot roots;
    return db.ReadTxRoots(key, roots) && roots.nTxRoot == NEVMCacheTestKey(value) &&
           roots.nReceiptRoot == NEVMCacheTestKey(value + 1);
}

// SYSCOIN: The caller has separately authenticated and synchronized this tip.
bool CompleteRootDisconnect(CNEVMTxRootsDB& db, const NEVMRootDisconnect& record, bool restore_root)
{
    return db.CompleteRootRecovery(NEVMCacheTestKey(99),
        restore_root ? std::make_optional(NEVMTxRoot{record.tx_root, record.receipt_root}) : std::nullopt);
}

template <typename Operation>
void CheckNEVMCacheWriteFailure(bool throw_error, Operation operation)
{
    if (throw_error) {
        BOOST_CHECK_THROW(operation(), dbwrapper_error);
    } else {
        BOOST_CHECK(!operation());
    }
}

template <typename Database>
void CheckNEVMCacheEraseRetries(const fs::path& path)
{
    const uint256 erased{NEVMCacheTestKey(1)};
    const uint256 retained{NEVMCacheTestKey(2)};
    for (const bool stored : {false, true}) {
        for (const bool throw_error : {false, true}) {
            FailingNEVMCacheDB<Database> db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            StageNEVMCacheValue(db, erased, 11);
            StageNEVMCacheValue(db, retained, 12);
            if (stored) BOOST_REQUIRE(db.FlushCacheToDisk(2, true));
            db.writes.clear();
            BOOST_REQUIRE(NEVMCacheValueMatches(db, erased, 11));

            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.FlushErase({erased}); });
            BOOST_CHECK(!NEVMCacheValueMatches(db, erased, 11));
            BOOST_CHECK_EQUAL(db.Exists(erased), stored);
            BOOST_CHECK(NEVMCacheValueMatches(db, retained, 12));

            // A failed retry must preserve the deletion and stop before writing puts.
            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.FlushCacheToDisk(2, false); });
            BOOST_CHECK(!NEVMCacheValueMatches(db, erased, 11));
            BOOST_CHECK_EQUAL(db.Exists(erased), stored);
            BOOST_CHECK(db.writes == std::vector<bool>({true, true}));

            // Stored rows exercise an erase-only retry with an empty put cache.
            BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
            BOOST_CHECK(!db.Exists(erased));
            BOOST_CHECK(!NEVMCacheValueMatches(db, erased, 11));
            BOOST_CHECK(db.Exists(retained));
            BOOST_CHECK(NEVMCacheValueMatches(db, retained, 12));
            const std::vector<bool> expected{stored ? std::vector<bool>{true, true, true} :
                                                     std::vector<bool>{true, true, true, false}};
            BOOST_CHECK(db.writes == expected);
            const auto writes{db.writes.size()};
            BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
            BOOST_CHECK_EQUAL(db.writes.size(), writes);
        }
    }
}

template <typename Database>
void CheckNEVMCacheReinsertion(const fs::path& path)
{
    const uint256 key{NEVMCacheTestKey(3)};
    for (const bool throw_error : {false, true}) {
        FailingNEVMCacheDB<Database> db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        StageNEVMCacheValue(db, key, 13);
        BOOST_REQUIRE(db.FlushCacheToDisk(2, true));
        db.writes.clear();
        db.FailNextWrite(throw_error);
        CheckNEVMCacheWriteFailure(throw_error, [&] { return db.FlushErase({key}); });
        BOOST_CHECK(!NEVMCacheValueMatches(db, key, 13));
        BOOST_REQUIRE(db.Exists(key));

        StageNEVMCacheValue(db, key, 23);
        BOOST_REQUIRE(NEVMCacheValueMatches(db, key, 23));
        BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
        BOOST_CHECK(db.writes == std::vector<bool>({true, false}));
        BOOST_CHECK(NEVMCacheValueMatches(db, key, 23));
        BOOST_CHECK(db.Exists(key));
        const auto writes{db.writes.size()};
        BOOST_REQUIRE(db.FlushCacheToDisk(2, true));
        BOOST_CHECK_EQUAL(db.writes.size(), writes);
        BOOST_CHECK(NEVMCacheValueMatches(db, key, 23));
    }
}

template <typename Database>
void CheckNEVMCacheNormalWritePolicy(const fs::path& path)
{
    for (const std::size_t chunk_items : {0U, 1U, 2U, 256U}) {
        for (const bool sync : {false, true}) {
            FailingNEVMCacheDB<Database> db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            for (unsigned char key{1}; key <= 5; ++key) StageNEVMCacheValue(db, NEVMCacheTestKey(key), key);
            BOOST_CHECK(db.writes.empty());
            BOOST_REQUIRE(db.FlushCacheToDisk(chunk_items, sync));
            const std::size_t expected_batches{chunk_items == 0 ? 1 : (5 + chunk_items - 1) / chunk_items};
            BOOST_CHECK(db.writes == std::vector<bool>(expected_batches, sync));
            BOOST_REQUIRE(db.FlushCacheToDisk(chunk_items, sync));
            BOOST_CHECK_EQUAL(db.writes.size(), expected_batches);
            BOOST_REQUIRE(db.FlushErase({NEVMCacheTestKey(1), NEVMCacheTestKey(2)}));
            BOOST_CHECK_EQUAL(db.writes.size(), expected_batches + 1);
            BOOST_CHECK(db.writes.back());
            BOOST_CHECK(!db.Exists(NEVMCacheTestKey(1)));
            BOOST_CHECK(!db.Exists(NEVMCacheTestKey(2)));
            BOOST_REQUIRE(db.FlushCacheToDisk(chunk_items, sync));
            BOOST_CHECK_EQUAL(db.writes.size(), expected_batches + 1);
        }
    }
}

template <typename Database>
void CheckNEVMCacheQueuedErase(const fs::path& path)
{
    FailingNEVMCacheDB<Database> db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
    const uint256 stored{NEVMCacheTestKey(1)};
    const uint256 cached{NEVMCacheTestKey(2)};
    StageNEVMCacheValue(db, stored, 11);
    BOOST_REQUIRE(db.FlushCacheToDisk(2, true));
    StageNEVMCacheValue(db, cached, 12);
    db.writes.clear();

    // Queue all stores' intents before a failure in the first store can prevent
    // the others from reaching their immediate FlushErase calls.
    db.EraseCache({stored, cached});
    BOOST_CHECK(db.writes.empty());
    BOOST_CHECK(!NEVMCacheValueMatches(db, stored, 11));
    BOOST_CHECK(!NEVMCacheValueMatches(db, cached, 12));
    BOOST_CHECK(db.Exists(stored));
    BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
    BOOST_CHECK(db.writes == std::vector<bool>({true}));
    BOOST_CHECK(!db.Exists(stored));
    BOOST_CHECK(!db.Exists(cached));
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(nevm_cache_retry_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(failed_erases_hide_stale_values_and_remain_retryable)
{
    CheckNEVMCacheEraseRetries<CNEVMMintedTxDB>(m_args.GetDataDirBase() / "mint_erase_retry");
    CheckNEVMCacheEraseRetries<CNEVMTxRootsDB>(m_args.GetDataDirBase() / "root_erase_retry");
}

BOOST_AUTO_TEST_CASE(reinserted_values_cancel_failed_erases)
{
    CheckNEVMCacheReinsertion<CNEVMMintedTxDB>(m_args.GetDataDirBase() / "mint_erase_reinsert");
    CheckNEVMCacheReinsertion<CNEVMTxRootsDB>(m_args.GetDataDirBase() / "root_erase_reinsert");
}

BOOST_AUTO_TEST_CASE(normal_flushes_keep_chunk_counts_and_sync_flags)
{
    CheckNEVMCacheNormalWritePolicy<CNEVMMintedTxDB>(m_args.GetDataDirBase() / "mint_batch_policy");
    CheckNEVMCacheNormalWritePolicy<CNEVMTxRootsDB>(m_args.GetDataDirBase() / "root_batch_policy");
}

BOOST_AUTO_TEST_CASE(queued_erases_survive_unattempted_immediate_writes)
{
    CheckNEVMCacheQueuedErase<CNEVMMintedTxDB>(m_args.GetDataDirBase() / "mint_erase_queued");
    CheckNEVMCacheQueuedErase<CNEVMTxRootsDB>(m_args.GetDataDirBase() / "root_erase_queued");
}

// SYSCOIN BEGIN: Cold reopening must preserve unfinished root revocation.
BOOST_AUTO_TEST_CASE(root_disconnect_journal_masks_reinsertions_across_reopen)
{
    const fs::path path{m_args.GetDataDirBase() / "root_disconnect_reopen"};
    const NEVMRootDisconnect record{NEVMCacheTestKey(1), NEVMCacheTestKey(2),
                                    NEVMCacheTestKey(13), NEVMCacheTestKey(14)};
    const uint256 unrelated{NEVMCacheTestKey(3)};
    for (const bool restore_root : {false, true}) {
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            StageNEVMCacheValue(db, record.block_hash, 13);
            BOOST_REQUIRE(db.FlushCacheToDisk());
            db.writes.clear();
            BOOST_REQUIRE(db.BeginDisconnect(record));
            BOOST_CHECK(db.writes == std::vector<bool>{true});
            BOOST_CHECK(!db.Exists(record.block_hash));
            BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
            BOOST_CHECK(!db.BeginDisconnect(record));

            // A delayed cache insertion must not cancel a durable revocation.
            StageNEVMCacheValue(db, record.block_hash, 23);
            StageNEVMCacheValue(db, unrelated, 33);
            BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 23));
            BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
            BOOST_CHECK(!db.Exists(record.block_hash));
            BOOST_CHECK(NEVMCacheValueMatches(db, unrelated, 33));
        }
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db({.path = path, .cache_bytes = 1 << 20});
            const auto pending{db.GetPendingDisconnect()};
            BOOST_REQUIRE(pending);
            BOOST_CHECK(pending->carrier == record.carrier);
            BOOST_CHECK(pending->block_hash == record.block_hash);
            BOOST_CHECK(pending->tx_root == record.tx_root);
            BOOST_CHECK(pending->receipt_root == record.receipt_root);
            BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
            BOOST_CHECK(NEVMCacheValueMatches(db, unrelated, 33));

            // The caller separately establishes and synchronizes the recovered
            // coins tip before choosing whether this carrier remains canonical.
            BOOST_REQUIRE(CompleteRootDisconnect(db, record, restore_root));
            BOOST_CHECK(db.writes == std::vector<bool>{true});
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_CHECK_EQUAL(NEVMCacheValueMatches(db, record.block_hash, 13), restore_root);
            BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 23));
        }
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_CHECK_EQUAL(NEVMCacheValueMatches(db, record.block_hash, 13), restore_root);
            BOOST_CHECK_EQUAL(db.Exists(record.block_hash), restore_root);
            BOOST_CHECK(NEVMCacheValueMatches(db, unrelated, 33));
        }
    }
}

BOOST_AUTO_TEST_CASE(root_disconnect_journal_write_failures_preserve_recovery_state)
{
    const fs::path path{m_args.GetDataDirBase() / "root_disconnect_failed_write"};
    const NEVMRootDisconnect record{NEVMCacheTestKey(1), NEVMCacheTestKey(2),
                                    NEVMCacheTestKey(13), NEVMCacheTestKey(14)};
    for (const bool throw_error : {false, true}) {
        for (const bool restore_root : {false, true}) {
            {
                FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                    {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
                StageNEVMCacheValue(db, record.block_hash, 13);
                BOOST_REQUIRE(db.FlushCacheToDisk());
                db.FailNextWrite(throw_error);
                CheckNEVMCacheWriteFailure(throw_error, [&] { return db.BeginDisconnect(record); });
                BOOST_CHECK(!db.GetPendingDisconnect());
                BOOST_CHECK(NEVMCacheValueMatches(db, record.block_hash, 13));
                BOOST_CHECK(db.Exists(record.block_hash));
            }
            {
                FailingNEVMCacheDB<CNEVMTxRootsDB> db({.path = path, .cache_bytes = 1 << 20});
                BOOST_CHECK(!db.GetPendingDisconnect());
                BOOST_REQUIRE(NEVMCacheValueMatches(db, record.block_hash, 13));
                BOOST_REQUIRE(db.BeginDisconnect(record));
                db.FailNextWrite(throw_error);
                CheckNEVMCacheWriteFailure(throw_error, [&] { return CompleteRootDisconnect(db, record, restore_root); });
                BOOST_REQUIRE(db.GetPendingDisconnect());
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
                StageNEVMCacheValue(db, record.block_hash, 23);
                BOOST_REQUIRE(db.FlushCacheToDisk(2, false));
                BOOST_CHECK(!db.Exists(record.block_hash));
            }
            {
                CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
                BOOST_REQUIRE(db.GetPendingDisconnect());
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 23));
                BOOST_REQUIRE(CompleteRootDisconnect(db, record, restore_root));
            }
            {
                CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
                BOOST_CHECK(!db.GetPendingDisconnect());
                BOOST_CHECK_EQUAL(NEVMCacheValueMatches(db, record.block_hash, 13), restore_root);
                BOOST_CHECK_EQUAL(db.Exists(record.block_hash), restore_root);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(root_disconnect_journal_preserves_opaque_roots_and_rejects_malformed_records)
{
    const fs::path path{m_args.GetDataDirBase() / "root_disconnect_malformed"};
    const DBParams params{.path = path, .cache_bytes = 1 << 20};
    const NEVMRootDisconnect record{NEVMCacheTestKey(1), NEVMCacheTestKey(2),
                                    NEVMCacheTestKey(13), NEVMCacheTestKey(14)};
    // Null NEVM fields remain opaque committed data; rollback must not add
    // restrictions absent from historical commitment validation.
    for (const unsigned int null_fields : {1U, 2U, 4U, 7U}) {
        auto opaque{record};
        if (null_fields & 1U) opaque.block_hash.SetNull();
        if (null_fields & 2U) opaque.tx_root.SetNull();
        if (null_fields & 4U) opaque.receipt_root.SetNull();
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            db.FlushDataToCache({{opaque.block_hash, NEVMTxRoot{opaque.tx_root, opaque.receipt_root}}});
            BOOST_REQUIRE(db.FlushCacheToDisk());
            BOOST_REQUIRE(db.BeginDisconnect(opaque));
        }
        {
            CNEVMTxRootsDB db(params);
            BOOST_REQUIRE(db.GetPendingDisconnect());
            NEVMTxRoot roots;
            BOOST_CHECK(!db.ReadTxRoots(opaque.block_hash, roots));
            BOOST_REQUIRE(CompleteRootDisconnect(db, opaque, /*restore_root=*/true));
        }
        {
            CNEVMTxRootsDB db(params);
            BOOST_CHECK(!db.GetPendingDisconnect());
            NEVMTxRoot roots;
            BOOST_REQUIRE(db.ReadTxRoots(opaque.block_hash, roots));
            BOOST_CHECK(roots.nTxRoot == opaque.tx_root);
            BOOST_CHECK(roots.nReceiptRoot == opaque.receipt_root);
        }
    }
    {
        auto invalid{record};
        invalid.carrier.SetNull();
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_CHECK(!db.BeginDisconnect(invalid));
            BOOST_CHECK(db.writes.empty());
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_REQUIRE(db.Write(uint8_t{'D'}, invalid, true));
        }
        BOOST_CHECK_THROW(CNEVMTxRootsDB{params}, dbwrapper_error);
    }
    {
        CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.Write(uint8_t{'D'}, uint8_t{1}, true));
    }
    BOOST_CHECK_THROW(CNEVMTxRootsDB{params}, dbwrapper_error);
    {
        CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.Write(uint8_t{'D'}, std::pair{record, uint8_t{1}}, true));
    }
    BOOST_CHECK_THROW(CNEVMTxRootsDB{params}, dbwrapper_error);
    {
        // The reserved one-byte key must not collide with a legacy root hash
        // whose first byte is the same journal tag.
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        StageNEVMCacheValue(db, NEVMCacheTestKey('D'), 13);
        BOOST_REQUIRE(db.FlushCacheToDisk());
    }
    CNEVMTxRootsDB db(params);
    BOOST_CHECK(!db.GetPendingDisconnect());
    BOOST_CHECK(NEVMCacheValueMatches(db, NEVMCacheTestKey('D'), 13));
}
// SYSCOIN END: Cold reopening must preserve unfinished root revocation.

// SYSCOIN BEGIN: Root publication coverage survives asynchronous puts and crashes.
BOOST_AUTO_TEST_CASE(published_root_tip_is_durable_before_asynchronous_cache_puts)
{
    const fs::path path{m_args.GetDataDirBase() / "root_published_tip"};
    const uint256 old_tip{NEVMCacheTestKey(10)};
    const uint256 new_tip{NEVMCacheTestKey(11)};
    const uint256 recovered_tip{NEVMCacheTestKey(15)};
    const uint256 root_hash{NEVMCacheTestKey(12)};
    for (const bool throw_error : {false, true}) {
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_CHECK(!db.RecordPublishedTip(uint256{}));
            BOOST_CHECK(db.writes.empty());
            BOOST_REQUIRE(db.RecordPublishedTip(old_tip));
            StageNEVMCacheValue(db, root_hash, 13);
            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.RecordPublishedTip(new_tip); });
            BOOST_REQUIRE(db.GetPublishedTip());
            BOOST_CHECK(*db.GetPublishedTip() == old_tip);
            BOOST_CHECK(db.writes == std::vector<bool>({true, true}));
            BOOST_CHECK(!db.Exists(root_hash));
        }
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db({.path = path, .cache_bytes = 1 << 20});
            BOOST_REQUIRE(db.GetPublishedTip());
            BOOST_CHECK(*db.GetPublishedTip() == old_tip);
            BOOST_CHECK(!db.Exists(root_hash));
            BOOST_REQUIRE(db.RecordPublishedTip(new_tip));
            BOOST_REQUIRE(db.RecordPublishedTip(new_tip));
            BOOST_CHECK(db.writes == std::vector<bool>{true});
            StageNEVMCacheValue(db, root_hash, 13);
            BOOST_REQUIRE(db.FlushCacheToDisk(2, /*fSync=*/false));
            BOOST_CHECK(db.writes == std::vector<bool>({true, false}));
        }
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
            BOOST_REQUIRE(db.GetPublishedTip());
            BOOST_CHECK(*db.GetPublishedTip() == new_tip);
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_CHECK(NEVMCacheValueMatches(db, root_hash, 13));
            BOOST_REQUIRE(db.CompleteRootRecovery(recovered_tip, std::nullopt));
        }
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
            BOOST_REQUIRE(db.GetPublishedTip());
            BOOST_CHECK(*db.GetPublishedTip() == recovered_tip);
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_CHECK(NEVMCacheValueMatches(db, root_hash, 13));
        }
    }
}

BOOST_AUTO_TEST_CASE(root_recovery_atomically_updates_publication_tip_and_canonical_alias)
{
    const fs::path path{m_args.GetDataDirBase() / "root_recovery_alias"};
    const NEVMRootDisconnect record{NEVMCacheTestKey(1), NEVMCacheTestKey(2),
                                    NEVMCacheTestKey(13), NEVMCacheTestKey(14)};
    const uint256 recovered_tip{NEVMCacheTestKey(20)};
    for (const bool throw_error : {false, true}) {
        for (const bool restore_alias : {false, true}) {
            const auto canonical_roots{restore_alias
                ? std::make_optional(NEVMTxRoot{NEVMCacheTestKey(23), NEVMCacheTestKey(24)})
                : std::nullopt};
            {
                FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                    {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
                BOOST_REQUIRE(db.RecordPublishedTip(record.carrier));
                StageNEVMCacheValue(db, record.block_hash, 13);
                BOOST_REQUIRE(db.FlushCacheToDisk());
                BOOST_REQUIRE(db.BeginDisconnect(record));
                BOOST_CHECK(!db.CompleteRootRecovery(uint256{}, canonical_roots));
                db.FailNextWrite(throw_error);
                CheckNEVMCacheWriteFailure(throw_error, [&] {
                    return db.CompleteRootRecovery(recovered_tip, canonical_roots);
                });
                BOOST_REQUIRE(db.GetPublishedTip());
                BOOST_CHECK(*db.GetPublishedTip() == record.carrier);
                BOOST_REQUIRE(db.GetPendingDisconnect());
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 23));
            }
            {
                FailingNEVMCacheDB<CNEVMTxRootsDB> db({.path = path, .cache_bytes = 1 << 20});
                BOOST_REQUIRE(db.GetPendingDisconnect());
                BOOST_REQUIRE(db.GetPublishedTip());
                BOOST_CHECK(*db.GetPublishedTip() == record.carrier);
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 23));
                BOOST_REQUIRE(db.CompleteRootRecovery(recovered_tip, canonical_roots));
                BOOST_CHECK(db.writes == std::vector<bool>{true});
            }
            {
                CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
                BOOST_REQUIRE(db.GetPublishedTip());
                BOOST_CHECK(*db.GetPublishedTip() == recovered_tip);
                BOOST_CHECK(!db.GetPendingDisconnect());
                BOOST_CHECK(!NEVMCacheValueMatches(db, record.block_hash, 13));
                BOOST_CHECK_EQUAL(NEVMCacheValueMatches(db, record.block_hash, 23), restore_alias);
                BOOST_CHECK_EQUAL(db.Exists(record.block_hash), restore_alias);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(published_root_tip_rejects_malformed_records_and_preserves_legacy_keys)
{
    const fs::path path{m_args.GetDataDirBase() / "root_published_tip_malformed"};
    const DBParams params{.path = path, .cache_bytes = 1 << 20};
    const uint256 tip{NEVMCacheTestKey(10)};
    const auto check_malformed = [&](const auto& value) {
        {
            CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_REQUIRE(db.Write(uint8_t{'T'}, value, true));
        }
        BOOST_CHECK_THROW(CNEVMTxRootsDB{params}, dbwrapper_error);
    };
    check_malformed(uint256{});
    check_malformed(uint8_t{1});
    check_malformed(std::pair{tip, uint8_t{1}});
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.RecordPublishedTip(tip));
        StageNEVMCacheValue(db, NEVMCacheTestKey('T'), 13);
        BOOST_REQUIRE(db.FlushCacheToDisk());
    }
    CNEVMTxRootsDB db(params);
    BOOST_REQUIRE(db.GetPublishedTip());
    BOOST_CHECK(*db.GetPublishedTip() == tip);
    BOOST_CHECK(NEVMCacheValueMatches(db, NEVMCacheTestKey('T'), 13));
}
// SYSCOIN END: Root publication coverage survives asynchronous puts and crashes.

BOOST_AUTO_TEST_SUITE_END()
// SYSCOIN END: Exercise real NEVM cache classes with failed batch writes.
