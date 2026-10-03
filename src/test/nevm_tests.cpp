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

#include <algorithm>
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

// Independent known-answer fixtures generated with syscoin/go-ethereum
// 2ce420e7892f7400296ad209dbe8efe3536e3f79: types.NewTx (legacy, EIP-2930,
// EIP-1559), types.DeriveSha(..., trie.NewStackTrie(nil)), types.CalcUncleHash,
// and rlp.EncodeToBytes(types.NewBlockWithHeader(header).WithBody(body)).
// Transactions cycle through the three fixed samples; receipts use matching
// types, status=1, cumulative gas=(index+1)*21000, and empty logs/bloom.
// Expected hashes are fixed Geth outputs, not a second C++ trie implementation.
const std::array<const char*, 3> GETH_INTEGRITY_TRANSACTIONS{{
    "df070b82520894000000000000000000000000000000000000123413421b0102",
    "a501e3821644080c8259d89400000000000000000000000000000000000012341443c0010203",
    "a602e482164409020e825dc09400000000000000000000000000000000000012341544c0010304",
}};
const char* const GETH_INTEGRITY_EMPTY_HEADER =
    "f901f7a00000000000000000000000000000000000000000000000000000000000000011a01dcc4de8dec75d7aab85b5"
    "67b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000022a00000000000"
    "000000000000000000000000000000000000000000000000000033a056e81f171bcc55a6ff8345e692c0f86e5b48e01b"
    "996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000012a8401c9c38080846553f10082a1b2a0000000000000000000000000000000"
    "0000000000000000000000000000000044880000000000000000";
const char* const GETH_INTEGRITY_WITHDRAWALS =
    "f864d8808094000000000000000000000000000000000000000080d80101940000000000000000000000000000000000"
    "00000080d8020294000000000000000000000000000000000000000080d8030394000000000000000000000000000000"
    "000000000080";

struct GethIntegrityVector {
    const char* name;
    unsigned count;
    unsigned mode;
    const char* hash;
    const char* tx_root;
    const char* receipt_root;
    const char* payload_hash;
};
const GethIntegrityVector GETH_INTEGRITY_VECTORS[]{
    {"empty", 0, 0,
        "9ad95c0544d8ee05d22dcfc00492ece945e1f6d9626fa14ba2042bddccd3c707",
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "c561c93625128e43251ac0f3a5ef63c846f94c2793e97a5b4e6dc23019e46681"},
    {"legacy", 1, 0,
        "6e10ea3ca8f516a45dde6e81482fb5c89d700966b7fd1630c96b23a888da8c25",
        "7194fe6103c5b692ff8c2a4b7c6c8d63d4435005163c4904c556572d564ea019",
        "056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
        "198331e1737283643c62007cb290dcaff261ce75e4086705b2fdd0cd8ff15574"},
    {"access_list", 1, 1,
        "8e8e37c9b4c812ddf39d63e7c7f7f8dbfc6b65a3bd782c506751765dbdb0e702",
        "19eb071c8a7905d149722223f505d9c70848d0b0901bf9210cb46de7068ea17d",
        "d3a6acf9a244d78b33831df95d472c4128ea85bf079a1d41e32ed0b7d2244c9e",
        "437299669136a1ffdc32d73b19f86ad39cd06fc8bb291045a8eb73926671ca14"},
    {"dynamic_fee", 1, 2,
        "c30ba882de3fe92eedb1b4b87afc04bd24ec2d48c9041c5cbb8e4caa7e98eb98",
        "c38475c3d10ceb94f1db4207b419a179aa75ec85f4f86fbcf0e40ee9801a5b77",
        "f78dfb743fbd92ade140711c8bbc542b5e307f0ab7984eff35d751969fe57efa",
        "81b8fafa97c5243cdbfb36684d22c8e946fef97454bd6251db827bc3466e57c3"},
    {"mixed", 3, 3,
        "14ee3df77ec5eeb8e38a5906f7ba580bb6b05bf068012c2b21444b301d7c4916",
        "02e0f16a80c772e4f59d025f9f6d1da3a230882fb3fdad4ad1050b44e7f95ffc",
        "75e70ade70d5adf91c651c207f7a6b91cbf69f7b90c37ffbab12479c27e6ad7e",
        "01f926f3dae07a0c166054ac385bc039652a268e684da153ae2dccade6a90cfe"},
    {"mixed127", 127, 3,
        "530dbaa884143c2b61c09b8590a4fe1399d66735dd51f0770d69de724a45516f",
        "3c27ea7e24d2e75e3f938028357d6bcd816eb4e8c1caf8f5351091d6181fcb7e",
        "c32824464906c244d0816d3cad1b7cdcda1fe8e61619920e31eb94c5561de9f1",
        "54d776925be5e4cf4dfa35491f31d806624a118e1c01844543fcff24f0d5cbea"},
    {"mixed128", 128, 3,
        "ae0c2b569113f6bb15fb9da85dfe87c955403ce0f77bfc284019683763621e49",
        "1cdbda4e0193ced95247e8c4a291545432709719b36476eadcbe590d76000f02",
        "282f27b326e02cc670b4306e83c707951e26fbf323b96b97c5d59b9779e2111a",
        "2feca3bceea7a40579ef1cd20200ba6402d28032df9f78a9e60522e2013baddf"},
    {"mixed129", 129, 3,
        "fc628f902762a35b954428f98e15b24686ffedbc2291c025a397be84d66a5844",
        "69053443267ee4917a101ffd221b3cb133351370d9beafc8fe311999547dd0d2",
        "372e1ebfca87139452fad483e11a2541b6dfb6449944394d791730a03f2711c9",
        "7308c7929abb76d64a218a5c0c8ec4641aa5f872be9595f396000077719ccbe5"},
    {"mixed255", 255, 3,
        "3a0695ca0f5b02f8750ac9d7997fa2049c23137af6cd1d224d7afaa4733b1c2e",
        "55d3ce9cad6bcdd85b0b152ee745a797552e529e4583666441cc7fd116047c29",
        "7104c19f285864fac5cd7e469d04bab1d4c5cf0d220f287b4c339915cc00f7aa",
        "9f756b4ee98f79579c29d5da6020cc732c07b2beb1bc212a39b3f36b0d29c46e"},
    {"mixed256", 256, 3,
        "96888a3b303fa3c4d0492009db1c975a3482c9bfbbf816a53719617f345e1a17",
        "463f557d04e1082aae98cfe27949d33608b080481c493a41b36e45ca3f8d1680",
        "9aded182deb7d43151a1722a83f05187735b46b288b2f3b37f25fb77da619375",
        "5743a11673f686048d9d30f38cc58206edc30851691661f3eaa6858ae0c0b2bb"},
    {"mixed257", 257, 3,
        "23adffad6eb4cde9794c749436c74dac9abfe02f420e158ce88a0beb1a4ff95d",
        "300c50b13adb7378f4fd5882430b4d27971d4e99183a03e0feafbca53fc984f1",
        "89b1c07c677f264194c031c4bfbcba85a869ef265def5c156601c1528df67132",
        "e9b4845dcb8c2a6afa93c659d4dcc242a9219daaccb7a81ec0e2cfeea55ac568"},
    {"withdrawals", 0, 4,
        "f33ef7b22c1839146b513847e3d936a75469c2077219f34c1b45645953a84ccc",
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "c15981703eb17f7cf70207d30ebb2c3b14a2ab597abf22a13985ff6635d7dc84"},
    {"uncles", 1, 5,
        "3c293b0e8e6b5adaeafb07c7994642fd6c5190c7b9057ca1d8155d0b18c396df",
        "7194fe6103c5b692ff8c2a4b7c6c8d63d4435005163c4904c556572d564ea019",
        "056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
        "00337c2aeb7814bde4db0b4c8b92c5d48cfba633435c26a32bc81a7e5128b793"},
    {"absent_withdrawals_placeholder", 1, 6,
        "56096eefb570079515a101357ac6e4dc1ee1fcc554dc5f4565809b3062adc303",
        "7194fe6103c5b692ff8c2a4b7c6c8d63d4435005163c4904c556572d564ea019",
        "056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
        "66672bbe9cfe45196e6588a72da1e63fc5b9a722c9ef184273bf0a74c0e4bc74"},
    {"complete_optional_header", 1, 7,
        "020bd14d5cc98a12bf5f6596ac67b080be10ce4a08eb28fccd4dc1ec088f2ead",
        "7194fe6103c5b692ff8c2a4b7c6c8d63d4435005163c4904c556572d564ea019",
        "056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
        "8e5b3f0891fef58796efb4b5ac720d3869ae7b4a1270ed45e3bcac09ef14f1a8"},
};

std::vector<dev::bytes> NEVMIntegrityItems(const dev::bytes& encoded)
{
    const dev::RLP list{encoded};
    std::vector<dev::bytes> result;
    for (size_t i{0}; i < list.itemCount(); ++i) result.push_back(list[i].data().toBytes());
    return result;
}

dev::bytes NEVMIntegrityList(const std::vector<dev::bytes>& items)
{
    dev::RLPStream stream{items.size()};
    for (const auto& item : items) stream.appendRaw(item);
    return stream.out();
}

dev::bytes NEVMIntegrityString(const dev::bytes& bytes)
{
    dev::RLPStream stream;
    stream.append(bytes);
    return stream.out();
}

uint256 NEVMIntegrityHash(const char* hex)
{
    const auto bytes{ParseHex(hex)};
    uint256 result;
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

CNEVMHeader NEVMIntegrityCommitment(const GethIntegrityVector& vector)
{
    CNEVMHeader header;
    header.nBlockHash = NEVMIntegrityHash(vector.hash);
    header.nTxRoot = NEVMIntegrityHash(vector.tx_root);
    header.nReceiptRoot = NEVMIntegrityHash(vector.receipt_root);
    return header;
}

dev::bytes NEVMIntegrityPayload(const GethIntegrityVector& vector)
{
    auto header{NEVMIntegrityItems(ParseHex(GETH_INTEGRITY_EMPTY_HEADER))};
    header[4] = NEVMIntegrityString(ParseHex(vector.tx_root));
    header[5] = NEVMIntegrityString(ParseHex(vector.receipt_root));
    dev::RLPStream gas;
    gas.append(vector.count * 21000);
    header[10] = gas.out();
    if (vector.mode >= 1) header.push_back({7});
    std::vector<dev::bytes> txs;
    for (unsigned i{0}; i < vector.count; ++i) {
        const unsigned type{vector.mode == 3 ? i % 3 : vector.mode <= 2 ? vector.mode : 0};
        txs.push_back(ParseHex(GETH_INTEGRITY_TRANSACTIONS[type]));
    }
    dev::bytes uncles{0xc0};
    if (vector.mode == 4) {
        header.push_back(NEVMIntegrityString(ParseHex("5e9c3572c4766d45b3c31df94da8779190a6736f7841700a3526a3cb52b4bf88")));
    } else if (vector.mode == 5) {
        auto uncle{NEVMIntegrityItems(ParseHex(GETH_INTEGRITY_EMPTY_HEADER))};
        uncle[8] = {41};
        uncle[12] = {0x81, 0x99};
        uncles = NEVMIntegrityList({NEVMIntegrityList(uncle)});
        header[1] = NEVMIntegrityString(ParseHex("b9b81d0122ce7c4019b97a5d13e20cfe4977cae2fae9d4d14dd6b9a337430b85"));
    } else if (vector.mode == 6) {
        // Geth can encode this nil optional placeholder, but cannot decode it as
        // common.Hash. Preflight must not authorize replay of that encoding.
        header.insert(header.end(), {{0x80}, {0x80}, {0x80}});
        header.push_back(NEVMIntegrityString(ParseHex(std::string(62, '0') + "66")));
    } else if (vector.mode == 7) {
        // Include every current optional field with an empty withdrawals body:
        // withdrawals root, blob gas, excess blob gas, beacon root, requests hash.
        header.push_back(NEVMIntegrityString(ParseHex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")));
        header.insert(header.end(), {{7}, {8}});
        header.push_back(NEVMIntegrityString(ParseHex(std::string(62, '0') + "66")));
        header.push_back(NEVMIntegrityString(ParseHex(std::string(62, '0') + "77")));
    }
    std::vector<dev::bytes> block{NEVMIntegrityList(header), NEVMIntegrityList(txs), uncles};
    if (vector.mode == 4) block.push_back(ParseHex(GETH_INTEGRITY_WITHDRAWALS));
    if (vector.mode == 7) block.push_back({0xc0});
    return NEVMIntegrityList(block);
}

void NEVMIntegrityRebindHeader(const dev::bytes& payload, CNEVMHeader& header)
{
    const auto block{NEVMIntegrityItems(payload)};
    const auto hash{dev::sha3(block[0])};
    std::copy(hash.begin(), hash.end(), header.nBlockHash.begin());
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


BOOST_AUTO_TEST_CASE(nevm_payload_integrity_matches_geth_trie_vectors)
{
    // Index RLP changes at 0/1, 127/128 and 255/256. Four small withdrawal
    // records additionally exercise inline (<32-byte) trie child references.
    for (const auto& vector : GETH_INTEGRITY_VECTORS) {
        BOOST_TEST_CONTEXT(vector.name) {
            const auto payload{NEVMIntegrityPayload(vector)};
            const auto hash{dev::sha3(payload)};
            BOOST_CHECK_EQUAL(HexStr(hash.asBytes()), vector.payload_hash);
            auto header{NEVMIntegrityCommitment(vector)};
            std::string error;
            if (vector.mode == 6) {
                BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(payload, header, error));
                BOOST_CHECK(!error.empty());
            } else {
                BOOST_CHECK_MESSAGE(CheckNEVMBlockPayloadIntegrity(payload, header, error), error);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(nevm_payload_integrity_rejects_changed_body_and_commitments)
{
    const auto& vector{GETH_INTEGRITY_VECTORS[4]};
    const auto original{NEVMIntegrityPayload(vector)};
    const auto reject{[&](const dev::bytes& payload) {
        auto header{NEVMIntegrityCommitment(vector)};
        std::string error;
        BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(payload, header, error));
        BOOST_CHECK(!error.empty());
    }};
    // A transaction's RLP remains valid while its committed content changes.
    auto block{NEVMIntegrityItems(original)};
    auto txs{NEVMIntegrityItems(block[1])};
    txs[0].back() ^= 1;
    block[1] = NEVMIntegrityList(txs);
    reject(NEVMIntegrityList(block));
    block = NEVMIntegrityItems(original);
    txs = NEVMIntegrityItems(block[1]);
    std::swap(txs[0], txs[1]);
    block[1] = NEVMIntegrityList(txs);
    reject(NEVMIntegrityList(block));

    for (unsigned field{0}; field < 3; ++field) {
        auto header{NEVMIntegrityCommitment(vector)};
        const std::array<uint256*, 3> hashes{&header.nBlockHash, &header.nTxRoot, &header.nReceiptRoot};
        hashes[field]->begin()[0] ^= 1;
        std::string error;
        BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(original, header, error));
    }
    // Match Core's changed header hash/root while retaining the old body: the
    // transaction commitment must still be independently recomputed.
    block = NEVMIntegrityItems(original);
    auto header_items{NEVMIntegrityItems(block[0])};
    auto header{NEVMIntegrityCommitment(vector)};
    header.nTxRoot.begin()[0] ^= 1;
    header_items[4] = NEVMIntegrityString(dev::bytes{header.nTxRoot.begin(), header.nTxRoot.end()});
    block[0] = NEVMIntegrityList(header_items);
    const auto changed{NEVMIntegrityList(block)};
    NEVMIntegrityRebindHeader(changed, header);
    std::string error;
    BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(changed, header, error));

    for (const unsigned index : {11U, 12U}) {
        const auto& body_vector{GETH_INTEGRITY_VECTORS[index]};
        auto body{NEVMIntegrityPayload(body_vector)};
        // Last byte belongs to a withdrawal amount or uncle nonce.
        body.back() ^= 1;
        auto body_header{NEVMIntegrityCommitment(body_vector)};
        BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(body, body_header, error));
    }
    // A committed withdrawals root requires the corresponding body list.
    auto withdrawals{NEVMIntegrityItems(NEVMIntegrityPayload(GETH_INTEGRITY_VECTORS[11]))};
    withdrawals.pop_back();
    auto withdrawal_header{NEVMIntegrityCommitment(GETH_INTEGRITY_VECTORS[11])};
    BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(NEVMIntegrityList(withdrawals), withdrawal_header, error));
}

BOOST_AUTO_TEST_CASE(nevm_payload_integrity_rejects_noncanonical_and_incomplete_rlp)
{
    const auto& vector{GETH_INTEGRITY_VECTORS[4]};
    const auto original{NEVMIntegrityPayload(vector)};
    const auto reject{[&](const dev::bytes& payload, bool rebind = false) {
        auto header{NEVMIntegrityCommitment(vector)};
        if (rebind) NEVMIntegrityRebindHeader(payload, header);
        std::string error;
        BOOST_CHECK(!CheckNEVMBlockPayloadIntegrity(payload, header, error));
        BOOST_CHECK(!error.empty());
    }};
    reject({});
    reject({0xc0});
    reject({0x80});
    reject({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    auto malformed{original};
    malformed.push_back(0x80);
    reject(malformed);
    for (const size_t size : {size_t{1}, size_t{3}, original.size() / 2, original.size() - 1}) {
        reject(dev::bytes{original.begin(), original.begin() + size});
    }
    // Non-minimal outer length and transaction-list length encode unchanged
    // body bytes, so rejection cannot be attributed to a changed trie root.
    malformed = original;
    ++malformed[0];
    malformed.insert(malformed.begin() + 1, 0);
    reject(malformed);
    auto block{NEVMIntegrityItems(original)};
    ++block[1][0];
    block[1].insert(block[1].begin() + 1, 0);
    reject(NEVMIntegrityList(block));

    // A typed transaction's RLP string wrapper must use minimal length form.
    block = NEVMIntegrityItems(original);
    auto txs{NEVMIntegrityItems(block[1])};
    const auto typed_size{static_cast<uint8_t>(txs[1][0] - 0x80)};
    txs[1][0] = 0xb8;
    txs[1].insert(txs[1].begin() + 1, typed_size);
    block[1] = NEVMIntegrityList(txs);
    reject(NEVMIntegrityList(block));

    block = NEVMIntegrityItems(original);
    block.push_back({0xc0}); // withdrawals without a header commitment
    reject(NEVMIntegrityList(block));
    block.push_back({0xc0}); // excess top-level field
    reject(NEVMIntegrityList(block));
    block = NEVMIntegrityItems(original);
    block[1] = {0x80}; // transaction body must be a list
    reject(NEVMIntegrityList(block));
    block = NEVMIntegrityItems(original);
    block[2] = {0x80}; // uncle body must be a list
    reject(NEVMIntegrityList(block));

    // Even a matching Core header hash does not authorize a noncanonical
    // scalar encoding or incomplete Ethereum header.
    for (unsigned mutation{0}; mutation < 2; ++mutation) {
        block = NEVMIntegrityItems(original);
        auto fields{NEVMIntegrityItems(block[0])};
        if (mutation == 0) fields[7] = {0x81, 1}; // noncanonical single byte
        if (mutation == 1) fields.resize(14); // missing nonce
        block[0] = NEVMIntegrityList(fields);
        reject(NEVMIntegrityList(block), true);
    }
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
        BOOST_CHECK_EXCEPTION(CNEVMTxRootsDB{params}, dbwrapper_error,
            [](const dbwrapper_error& error) {
                return std::string{error.what()} == "Invalid pending NEVM root disconnect record";
            });
    }
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.Write(uint8_t{'D'}, uint8_t{1}, true));
    }
    BOOST_CHECK_EXCEPTION(CNEVMTxRootsDB{params}, dbwrapper_error,
        [](const dbwrapper_error& error) {
            return std::string{error.what()} == "Invalid pending NEVM root disconnect record";
        });
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.Write(uint8_t{'D'}, std::pair{record, uint8_t{1}}, true));
    }
    BOOST_CHECK_EXCEPTION(CNEVMTxRootsDB{params}, dbwrapper_error,
        [](const dbwrapper_error& error) {
            return std::string{error.what()} == "Invalid pending NEVM root disconnect record";
        });
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
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_REQUIRE(db.Write(uint8_t{'T'}, value, true));
        }
        BOOST_CHECK_EXCEPTION(CNEVMTxRootsDB{params}, dbwrapper_error,
            [](const dbwrapper_error& error) {
                return std::string{error.what()} == "Invalid published NEVM root tip record";
            });
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

BOOST_AUTO_TEST_CASE(root_undo_preserves_absence_zero_tuples_and_canonical_aliases)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_aliases"};
    const uint256 parent{NEVMCacheTestKey(1)}, first{NEVMCacheTestKey(2)},
        second{NEVMCacheTestKey(3)}, third{NEVMCacheTestKey(4)};
    const uint256 hash{};
    const NEVMTxRoot zero{}, changed{NEVMCacheTestKey(11), NEVMCacheTestKey(12)};
    CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
    NEVMRootUndo undo;
    BOOST_CHECK(!db.ReadRootUndo(first, undo));
    db.StageConnect(first, parent, hash, zero);
    BOOST_REQUIRE(db.ReadRootUndo(first, undo));
    BOOST_CHECK(undo.parent == parent);
    BOOST_CHECK(undo.block_hash.IsNull());
    BOOST_CHECK(!undo.previous);
    BOOST_CHECK(undo.roots.nTxRoot.IsNull());
    BOOST_REQUIRE(db.FlushCacheToDisk());

    db.StageConnect(second, first, hash, changed);
    BOOST_REQUIRE(db.ReadRootUndo(second, undo));
    BOOST_REQUIRE(undo.previous);
    BOOST_CHECK(undo.previous->nTxRoot.IsNull());
    BOOST_CHECK(undo.previous->nReceiptRoot.IsNull());
    BOOST_CHECK(undo.roots.nTxRoot == changed.nTxRoot);
    // An alias with identical roots still has a present predecessor.
    db.StageConnect(third, second, hash, changed);
    BOOST_REQUIRE(db.ReadRootUndo(third, undo));
    BOOST_REQUIRE(undo.previous);
    BOOST_CHECK(undo.previous->nTxRoot == changed.nTxRoot);
    BOOST_CHECK(undo.previous->nReceiptRoot == changed.nReceiptRoot);
    BOOST_REQUIRE(db.FlushCacheToDisk());
}

BOOST_AUTO_TEST_CASE(root_undo_exact_retries_never_capture_the_child_as_parent)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_retry"};
    const uint256 parent{NEVMCacheTestKey(1)}, first{NEVMCacheTestKey(2)},
        second{NEVMCacheTestKey(3)}, hash{NEVMCacheTestKey(4)};
    const NEVMTxRoot old_roots{NEVMCacheTestKey(11), NEVMCacheTestKey(12)},
        new_roots{NEVMCacheTestKey(21), NEVMCacheTestKey(22)};
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        db.StageConnect(first, parent, hash, old_roots);
        db.StageConnect(first, parent, hash, old_roots);
        NEVMRootUndo undo;
        BOOST_REQUIRE(db.ReadRootUndo(first, undo));
        BOOST_CHECK(!undo.previous);
        db.StageConnect(second, first, hash, new_roots);
        db.StageConnect(second, first, hash, new_roots);
        BOOST_REQUIRE(db.FlushCacheToDisk());
    }
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
        db.StageConnect(second, first, hash, new_roots);
        NEVMRootUndo undo;
        BOOST_REQUIRE(db.ReadRootUndo(second, undo));
        BOOST_REQUIRE(undo.previous);
        BOOST_CHECK(undo.previous->nTxRoot == old_roots.nTxRoot);
        BOOST_CHECK(undo.previous->nReceiptRoot == old_roots.nReceiptRoot);
        BOOST_CHECK_THROW(db.StageConnect(second, parent, hash, new_roots), dbwrapper_error);
        BOOST_CHECK_THROW(db.StageConnect(second, first, NEVMCacheTestKey(5), new_roots), dbwrapper_error);
        BOOST_CHECK_THROW(db.StageConnect(second, first, hash, old_roots), dbwrapper_error);

        // A real reconnect observes the recorded parent tuple again.
        db.FlushDataToCache({{hash, old_roots}});
        db.StageConnect(second, first, hash, new_roots);
        BOOST_REQUIRE(db.ReadRootUndo(second, undo));
        BOOST_REQUIRE(undo.previous);
        BOOST_CHECK(undo.previous->nTxRoot == old_roots.nTxRoot);
        db.FlushDataToCache({{hash, NEVMTxRoot{NEVMCacheTestKey(31), NEVMCacheTestKey(32)}}});
        BOOST_CHECK_THROW(db.StageConnect(second, first, hash, new_roots), dbwrapper_error);
        BOOST_CHECK(NEVMCacheValueMatches(db, hash, 31));
    }
}

BOOST_AUTO_TEST_CASE(root_undo_is_write_ahead_and_failed_writes_remain_retryable)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_failed_write"};
    const uint256 parent{NEVMCacheTestKey(1)}, carrier{NEVMCacheTestKey(2)}, hash{NEVMCacheTestKey(3)};
    const NEVMTxRoot roots{NEVMCacheTestKey(11), NEVMCacheTestKey(12)};
    const auto undo_key{std::make_pair(uint8_t{'U'}, carrier)};
    for (const bool throw_error : {false, true}) {
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            db.StageConnect(carrier, parent, hash, roots);
            BOOST_CHECK(db.writes.empty());
            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.RecordPublishedTip(carrier); });
            BOOST_CHECK(!db.GetPublishedTip());
            BOOST_CHECK(!db.Exists(undo_key));
            BOOST_CHECK(!db.Exists(hash));
            NEVMRootUndo undo;
            BOOST_REQUIRE(db.ReadRootUndo(carrier, undo));
            BOOST_CHECK(!undo.previous);

            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.FlushCacheToDisk(1, false); });
            BOOST_CHECK(!db.Exists(undo_key));
            BOOST_CHECK(!db.Exists(hash));
            BOOST_REQUIRE(db.RecordPublishedTip(carrier));
            BOOST_REQUIRE(db.Exists(undo_key));
            BOOST_CHECK(!db.Exists(hash));
            BOOST_CHECK(db.writes == std::vector<bool>({true, false, true, true}));
            // Root publication may fail independently after its undo is durable.
            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.FlushCacheToDisk(1, false); });
            BOOST_CHECK(!db.Exists(hash));
        }
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
            BOOST_CHECK(db.GetPublishedTip() == carrier);
            NEVMRootUndo undo;
            BOOST_REQUIRE(db.ReadRootUndo(carrier, undo));
            BOOST_CHECK(!undo.previous);
            db.StageConnect(carrier, parent, hash, roots);
            BOOST_REQUIRE(db.FlushCacheToDisk(1, false));
            BOOST_CHECK(NEVMCacheValueMatches(db, hash, 11));
        }
    }
}

BOOST_AUTO_TEST_CASE(root_undo_flush_retries_keep_every_unwritten_record)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_flush_retry"};
    const uint256 parent{NEVMCacheTestKey(1)}, first{NEVMCacheTestKey(2)},
        second{NEVMCacheTestKey(3)}, hash{NEVMCacheTestKey(4)};
    FailingNEVMCacheDB<CNEVMTxRootsDB> db(
        {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
    const auto empty_memory{db.GetRootUndoMemoryUsage()};
    db.StageConnect(first, parent, hash, NEVMTxRoot{});
    db.StageConnect(second, first, hash, NEVMTxRoot{NEVMCacheTestKey(11), NEVMCacheTestKey(12)});
    const auto staged_memory{db.GetRootUndoMemoryUsage()};
    BOOST_CHECK_GT(staged_memory, empty_memory);
    db.FailNextWrite(false);
    BOOST_CHECK(!db.FlushRootUndo());
    BOOST_CHECK_EQUAL(db.GetRootUndoMemoryUsage(), staged_memory);
    NEVMRootUndo undo;
    BOOST_REQUIRE(db.ReadRootUndo(first, undo));
    BOOST_CHECK(!undo.previous);
    BOOST_REQUIRE(db.ReadRootUndo(second, undo));
    BOOST_REQUIRE(undo.previous);
    BOOST_CHECK(undo.previous->nTxRoot.IsNull());
    BOOST_REQUIRE(db.FlushRootUndo(false));
    BOOST_CHECK_LT(db.GetRootUndoMemoryUsage(), staged_memory);
    BOOST_REQUIRE(db.Exists(std::make_pair(uint8_t{'U'}, first)));
    BOOST_REQUIRE(db.Exists(std::make_pair(uint8_t{'U'}, second)));
    BOOST_CHECK(!db.Exists(hash));
    const auto writes{db.writes.size()};
    BOOST_REQUIRE(db.FlushRootUndo());
    BOOST_CHECK_EQUAL(db.writes.size(), writes);
}

BOOST_AUTO_TEST_CASE(root_disconnect_persists_a_cached_inverse_before_revocation)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_disconnect_barrier"};
    const uint256 parent{NEVMCacheTestKey(1)}, carrier{NEVMCacheTestKey(2)}, hash{NEVMCacheTestKey(3)};
    const NEVMTxRoot roots{NEVMCacheTestKey(11), NEVMCacheTestKey(12)};
    const NEVMRootDisconnect record{carrier, hash, roots.nTxRoot, roots.nReceiptRoot};
    for (const bool throw_error : {false, true}) {
        {
            FailingNEVMCacheDB<CNEVMTxRootsDB> db(
                {.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            db.StageConnect(carrier, parent, hash, roots);
            db.FailNextWrite(throw_error);
            CheckNEVMCacheWriteFailure(throw_error, [&] { return db.BeginDisconnect(record); });
            BOOST_CHECK(!db.GetPendingDisconnect());
            BOOST_CHECK(!db.Exists(uint8_t{'D'}));
            BOOST_CHECK(NEVMCacheValueMatches(db, hash, 11));
            BOOST_REQUIRE(db.BeginDisconnect(record));
            BOOST_CHECK(db.writes == std::vector<bool>({true, true, true}));
        }
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.GetPendingDisconnect());
        NEVMRootUndo undo;
        BOOST_REQUIRE(db.ReadRootUndo(carrier, undo));
        BOOST_CHECK(undo.parent == parent);
        BOOST_CHECK(!undo.previous);
        BOOST_CHECK(!NEVMCacheValueMatches(db, hash, 11));
    }
}

BOOST_AUTO_TEST_CASE(root_schema_and_undo_reject_missing_legacy_or_malformed_metadata)
{
    const fs::path path{m_args.GetDataDirBase() / "root_undo_malformed"};
    const DBParams params{.path = path, .cache_bytes = 1 << 20};
    const uint256 parent{NEVMCacheTestKey(1)}, carrier{NEVMCacheTestKey(2)}, hash{NEVMCacheTestKey(3)};
    const auto undo_key{std::make_pair(uint8_t{'U'}, carrier)};
    {
        CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
        BOOST_REQUIRE(db.Write(hash, NEVMTxRoot{}, true));
    }
    BOOST_CHECK_EXCEPTION(CNEVMTxRootsDB{params}, dbwrapper_error,
        [](const dbwrapper_error& error) { return std::string{error.what()}.find("-reindex") != std::string::npos; });
    const auto check_schema = [&](const auto& value) {
        {
            CDBWrapper db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_REQUIRE(db.Write(uint8_t{'V'}, value, true));
        }
        BOOST_CHECK_THROW(CNEVMTxRootsDB{params}, dbwrapper_error);
    };
    check_schema(uint32_t{0});
    check_schema(uint32_t{2});
    check_schema(uint8_t{1});
    check_schema(std::pair{uint32_t{1}, uint8_t{0}});

    const NEVMRootUndo valid{parent, hash, NEVMTxRoot{}, std::nullopt};
    const auto check_undo = [&](const auto& value) {
        {
            CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true});
            BOOST_REQUIRE(db.Write(undo_key, value, true));
        }
        CNEVMTxRootsDB db(params);
        NEVMRootUndo undo;
        BOOST_CHECK_THROW(db.ReadRootUndo(carrier, undo), dbwrapper_error);
        BOOST_CHECK_THROW(db.StageConnect(carrier, parent, hash, NEVMTxRoot{}), dbwrapper_error);
        BOOST_CHECK(!db.Exists(hash));
    };
    check_undo(uint8_t{1});
    check_undo(uint8_t{2});
    check_undo(std::pair{valid, uint8_t{0}});
    check_undo(std::pair{std::pair{std::pair{std::pair{uint8_t{1}, parent}, hash}, NEVMTxRoot{}}, uint8_t{2}});
    check_undo(NEVMRootUndo{uint256{}, hash, NEVMTxRoot{}, std::nullopt});
    check_undo(NEVMRootUndo{carrier, hash, NEVMTxRoot{}, std::nullopt});
    {
        CNEVMTxRootsDB db({.path = path, .cache_bytes = 1 << 20, .wipe_data = true, .obfuscate = true});
        db.StageConnect(carrier, parent, hash, NEVMTxRoot{});
        BOOST_REQUIRE(db.FlushCacheToDisk());
    }
    CNEVMTxRootsDB db(params);
    NEVMRootUndo undo;
    BOOST_REQUIRE(db.ReadRootUndo(carrier, undo));
    BOOST_CHECK(!undo.previous);
}

BOOST_AUTO_TEST_SUITE_END()
// SYSCOIN END: Exercise real NEVM cache classes with failed batch writes.
